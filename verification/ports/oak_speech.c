#include "port_state.h"

void port_prepare_oak_speech(struct cpu_register_state *, port_u8 *);

/* Port of OakSpeech through the PrepareOakSpeech call boundary in
 * engine/movie/oak_speech/oak_speech.asm. The remaining intro dialogue and
 * naming choreography remain outside this proof domain. */
__attribute__((noinline, used)) void
port_oak_speech(struct cpu_register_state *state, port_u8 *memory)
{
	/* PlaySound, PlayMusic, ClearScreen, and LoadTextBoxTilePatterns are
	 * matched call boundaries before the real PrepareOakSpeech port. */
	port_prepare_oak_speech(state, memory);
}
