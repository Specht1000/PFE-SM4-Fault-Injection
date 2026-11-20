"""Voltage-glitch campaign on the STM32F303 SM4 target, with DFA filtering."""
from glitch_common import run_campaign


def configure_attack(scope, driver):
    # Keep the normal target clock. Route a short pulse to ONE crowbar MOSFET.
    # The scope's Glitch SMA must be connected to the target's intended VCC path.
    scope.io.hs2 = "clkgen"
    scope.glitch.output = "glitch_only"

    if driver == "hp":
        scope.io.glitch_hp = True
    else:
        scope.io.glitch_lp = True


if __name__ == "__main__":
    raise SystemExit(run_campaign("voltage", configure_attack))
