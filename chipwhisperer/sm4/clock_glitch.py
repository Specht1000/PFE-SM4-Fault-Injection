"""Clock-glitch campaign on the STM32F303 SM4 target, with DFA filtering."""
from glitch_common import run_campaign


def configure_attack(scope, driver):
    # Forward the scope-generated clock through its XOR glitch block.
    # The target must use the clock supplied on HS2, as in the normal client.
    scope.glitch.output = "clock_xor"
    scope.io.hs2 = "glitch"


if __name__ == "__main__":
    raise SystemExit(run_campaign("clock", configure_attack))
