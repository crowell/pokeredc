#include "port_state.h"

static void
serial_inc_a(struct cpu_register_state *r)
{
	port_u8 old = r->a;
	port_u8 carry = r->f & PORT_FLAG_C;
	r->a++;
	r->f = carry;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 15) r->f |= PORT_FLAG_H;
}

static void
serial_cp(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->f = PORT_FLAG_N;
	if (left == right) r->f |= PORT_FLAG_Z;
	if ((left & 15) < (right & 15)) r->f |= PORT_FLAG_H;
	if (left < right) r->f |= PORT_FLAG_C;
}

/* Returns 1 when no connection has been established, otherwise 0. */
__attribute__((noinline, used)) port_u8
port_serial_interrupt_begin(struct serial_interrupt_state *s)
{
	s->saved_registers = s->registers;
	s->registers.a = s->connection_status;
	serial_inc_a(&s->registers);
	return s->registers.a == 0;
}

__attribute__((noinline, used)) void
port_serial_interrupt_established(struct serial_interrupt_state *s)
{
	s->registers.a = s->serial_data;
	s->receive_data = s->registers.a;
	s->registers.a = s->send_data;
	s->serial_data = s->registers.a;
	s->registers.a = s->connection_status;
	serial_cp(&s->registers, 2);
	if ((s->registers.f & PORT_FLAG_Z) == 0) {
		s->registers.a = 0x80;
		s->serial_control = s->registers.a;
	}
}

/* Returns 1 to read the divider, or 0 for the internal-clock path. */
__attribute__((noinline, used)) port_u8
port_serial_interrupt_unestablished(struct serial_interrupt_state *s)
{
	s->registers.a = s->serial_data;
	s->receive_data = s->registers.a;
	s->connection_status = s->registers.a;
	serial_cp(&s->registers, 2);
	s->registers.a = 0;
	s->registers.f = PORT_FLAG_Z;
	s->serial_data = s->registers.a;
	if (s->connection_status == 2)
		return 0;
	s->registers.a = 3;
	s->divider = s->registers.a;
	return 1;
}

/* Returns 1 while bit 7 is set, or 0 after starting external transfer. */
__attribute__((noinline, used)) port_u8
port_serial_interrupt_divider_step(struct serial_interrupt_state *s)
{
	port_u8 carry = s->registers.f & PORT_FLAG_C;
	s->registers.a = s->observed_divider;
	s->registers.f = carry | PORT_FLAG_H;
	if ((s->registers.a & 0x80) == 0)
		s->registers.f |= PORT_FLAG_Z;
	if ((s->registers.a & 0x80) != 0)
		return 1;
	s->registers.a = 0x80;
	s->serial_control = s->registers.a;
	return 0;
}

__attribute__((noinline, used)) void
port_serial_interrupt_finish(struct serial_interrupt_state *s)
{
	s->registers.a = 1;
	s->received_new_data = s->registers.a;
	s->registers.a = 0xfe;
	s->send_data = s->registers.a;
	s->registers = s->saved_registers;
}

/* Port of Serial in home/serial.asm. */
__attribute__((noinline, used)) void
port_serial_interrupt(struct serial_interrupt_state *s,
	const port_u8 *divider_observations)
{
	port_u16 index = 0;
	if (port_serial_interrupt_begin(s)) {
		if (port_serial_interrupt_unestablished(s)) {
			do {
				s->observed_divider = divider_observations[index++];
			} while (port_serial_interrupt_divider_step(s));
		}
	} else {
		port_serial_interrupt_established(s);
	}
	port_serial_interrupt_finish(s);
}
