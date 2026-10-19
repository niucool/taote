# T-009 — the usart `step()` device bridge is a silent no-op, and it lives in the wrong class

| field | value |
|---|---|
| severity | **low** (silently drops forwarded bytes; a documented-away stub) |
| area | `qiling/hw/stm32f4xx_usart.cpp:34-48` (`STM32F4xxUsart::step`), `qiling/hw/connectivity.hpp:82-95` |
| upstream | `qiling/hw/connectivity.py:108-124` (`QlConnectivityPeripheral.device_handler`) |
| found in | `063d5a2` (the usart family slice) |
| status | open |

## What is wrong

The upstream bridge is a decorator on the *base* class, so every connectivity
peripheral gets it for free:

```python
# qiling/hw/connectivity.py:108-124
@staticmethod
def device_handler(func):
    def wrapper(self):
        if len(self.device_list) > 0:
            if self.otube.readable():
                data = self.recv(1)
                for device in self.device_list:
                    device.send(data)
            for device in self.device_list:
                device.step()
        func(self)
    return wrapper
```

In the port the code is in the usart subclass and its body is empty:

```cpp
// qiling/hw/stm32f4xx_usart.cpp:34-48
void STM32F4xxUsart::step() {
    if (!device_list().empty()) {
        if (otube().readable()) {
            // the device bridge rides the chardev slice (the upstream sends
            // the byte to each connected device)
        }
    }

    transfer();
    check_interrupt();
}
```

So when a profile *does* connect devices (`QlConnectivityPeripheral::connect`,
`connectivity.hpp:86-90`), the port silently:

- never moves the output byte into the peer's input tube, and
- never calls the peer's `step()`.

That is not a "not built yet" that fails loudly — it is an empty `if` body that
makes the class look implemented. `device_list()` is public and populated by
`connect()`, so a test or a profile can reach this state today.

Two structural notes that make the fix cheaper now than later:

- the bridge belongs on `QlConnectivityPeripheral` (a protected
  `step_devices()` helper the subclasses call from their `step()`), otherwise
  every future i2c/spi/dma/uart peripheral re-implements it;
- `device_list_` holds raw `QlPeripheral*` (`connectivity.hpp:137`) into
  `QlHwManager::entity_` — fine while the manager owns the peripherals, but
  `QlHwManager::destroy` erases entities without invalidating the lists → a
  dangling device pointer there. Worth a comment at minimum.

## Suggested fix

Implement the base helper (upstream shape), call it from the usart's `step()`
before `transfer()`:

```cpp
// connectivity.hpp (protected)
void step_devices() {
    if (device_list_.empty()) return;
    if (otube_.readable()) {
        const auto data = recv(1);
        for (auto* device : device_list_) {
            if (auto* conn = dynamic_cast<QlConnectivityPeripheral*>(device)) {
                conn->send(data);
            }
        }
    }
    for (auto* device : device_list_) {
        device->step();
    }
}
```

If the chardev slice is genuinely not ready, the alternative is to keep the
stub but make it loud: `throw QlErrorNotImplemented(...)` when
`device_list()` is non-empty (matching how `os/mcu.cpp:28-30` handles the fast
mode). Either way, drop the empty `if`.

## Acceptance test

`tests/Hw_Test.cpp`:

- create two usart peripherals, `a->connect(b)`; push a byte into `a`'s output
  tube (`a->write_body(kDrOffset, 4, 'x')`); `a->step()`; assert `b->has_input()`
  and `b->recv_from_user() == 'x'` (fails today), and that `b`'s `step()`
  effects ran (e.g. `b`'s SR gained RXNE).
