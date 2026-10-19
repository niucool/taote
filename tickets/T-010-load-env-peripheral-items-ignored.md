# T-010 — `load_env` silently ignores `type == "peripheral"` records (no `load_all`)

| field | value |
|---|---|
| severity | **low** (a profile's peripherals load as nothing, with no error) |
| area | `qiling/loader/mcu.cpp:135-180` (`QlLoaderMCU::load_env`, the `peripheral` branch at 170) |
| upstream | `qiling/loader/mcu.py:109-133` (`load_env`) + `qiling/hw/hw.py:96-99` (`QlHwManager.load_all`) |
| found in | `22d0f91` (the intc slice landed the loader core) |
| status | open |

## What is wrong

```cpp
// qiling/loader/mcu.cpp:170-175
} else if (type == "peripheral") {
    // the peripheral items ride the explicit create calls (the
    // upstream load_all path — the test harness creates them)
} else {
    // the unknown types log-and-ignore (the upstream debug walk)
}
```

Upstream handles the `peripheral` memory type by instantiating the entity from
the env record itself:

```python
# qiling/hw/hw.py:96-99
def load_all(self):
    for label, args in self.ql.env.items():
        if args['type'] == 'peripheral':
            self.create(label.lower(), args['struct'], args['base'], args.get("kwargs", {}))
```

The port's `create(label, struct, base, kwargs)` and the whole factory registry
already exist (`QlHwManager::create`, `qiling/hw/hw.cpp`), and the env record
format used by the port (`type;struct;base;key=value…`) carries exactly the
three fields `load_all` needs — the `core` branch right above (155-169) already
parses them. So this is not "the machinery is missing"; it is a branch that was
left empty.

Consequences: a board profile that declares its peripherals the upstream way
(`{"GPIOA": "peripheral;STM32F1xxGpio;0x40010800"}`) loads **nothing** and the
emulation continues with the registers unmapped/regions absent — the failure
shows up much later as a mysterious mmio read/write, if at all. `STATUS.md:1188`
notes the stm32f103 board table + the `load_env` `peripheral` items "ride the
board-assembly slice", so this is a known gap — but a known gap that is
currently silent, which the port's own convention ("no silent stubs") rejects.

## Suggested fix

Either implement the branch (cheap — the `core` branch is the template, and
`struct`/`base` are `parts[1]`/`parts[2]`):

```cpp
} else if (type == "peripheral" && parts.size() >= 3) {
    QlHwManager::PeripheralKwargs kwargs;
    for (std::size_t i = 3; i < parts.size(); ++i) { /* the same key=value parse */ }
    lower = lowercase(name);
    if (ql_->hw()->create(lower, parts[1], number(parts[2]), kwargs) == nullptr) {
        throw QlErrorBase("mcu load_env: unknown peripheral struct '" + parts[1] + "' for '" + name + "'");
    }
}
```

or make the deferral loud:

```cpp
} else if (type == "peripheral") {
    throw QlErrorNotImplemented("mcu load_env: the 'peripheral' records land with the board-assembly slice");
}
```

Note the `create()` nullptr case (the factory lookup miss,
`QlHwManager::create` in `qiling/hw/hw.cpp`): upstream logs a warning and
returns `None`; the port returns `nullptr` with no log at all — a profile typo
in the struct name would be as silent as this branch. Give it at least the
upstream warning.

## Acceptance test

`tests/Hw_Test.cpp`: build the env with a
`{"GPIOA", "peripheral;STM32F1xxGpio;0x40010800"}` record; assert
`ql.hw()->peripheral("gpioa") != nullptr` and that its region resolves (fails
today), or assert the thrown `QlErrorNotImplemented` if the loud-deferral
option is taken. Keep the existing `core`-record fixtures green.
