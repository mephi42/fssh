`fssh` - execute program via SSH, while tolerating TCP connection losses

Implementation is work in progress.

Executables:
- `fssh` - client-side `ssh` drop-in replacement
- `fssh-fwd` - server-side wrapper, executed by `fssh`
- `fssh-daemon` - server-side daemon, that starts and shepherds user-speficied executable

Files:
- `/tmp/fssh-<guid>` - domain socket, through which `fssh-fwd` and `fssh-daemon` talk

Flow:
- `fssh user@host pgm args...` spawns `ssh user@host fssh-fwd <guid> pgm args...`, where `<guid>` is random `[0-9a-f]{32}` character sequence.
If `ssh` terminates for any reason, `fssh` respawns it.
- `fssh-fwd <guid> pgm args...` tries to connect to domain socket `/tmp/fssh-<guid>`.
If unsuccessful, it creates this domain socket, starts listening on it, and spawns `fss-daemon <guid> pgm args...`, to which it hands the listening domain socket over.
It then starts forwarding data between the domain socket and its own stdin/stdout.
- `fssh-daemon <guid> pgm args...` spawns `pgm args...` and accepts connections on the domain socket.
Thanks to `fssh-fwd`, it effectively talks to `fssh` via the domain socket.
During execution of `pgm`, `fssh` and `fssh-daemon` keep running, while `fssh-fwd` might be restarted multiple times due to TCP connection losses.
In order to guarantee that no input or output is lost, `fssh` and `fssh-daemon` communicate using buffer synchronization protocol.

Each side keeps an input and an output buffers.
Sides exchange messages in the following format:
```
+------------------+------------------+------------------------------------+
|  Type (uint8_t)  | Stream (uint8_t) |    Length (big-endian uint16_t)    |
+------------------+------------------+------------------------------------+
|                                                                          |
|                                     Payload                              |
|                                                                          |
+--------------------------------------------------------------------------+
```
Outgoing messages are appended to the output buffer. Incoming messages are received directly into the input buffer.
There are three message types: data (type 0), status (type 1) and acknowledgement (type 2).
Data message carries payload for one of the three streams (0 - stdin, 1 - stdout, 2 - stderr). Upon receipt, its payload is dispatched accordingly, and an acknowledgement message is appended to the output buffer.
Status message's stream field is ignored, and payload is big-endian `uint32\_t`, as returned by `wait(2)`.
When an acknowledgement message is received, its stream field is ignored, its payload is interpreted as a big-endian `uint64\_t` byte index, and bytes up to this index are discarded from the output buffer.

Random thoughts:
- One should be able to replace `ssh` with other command using `FSSH_SSH` environment variable.
- An echo, character generation and character consumption programs can be used to measure performance in the following scenarios:
    - `test_generate | test_echo | test_consume`
    - `test_generate | FSSH_SSH='test_local' fssh test_echo | test_consume` (`test_local` can also be used for error injection)
    - `test_generate | fssh localhost test_echo | test_consume`
    - `test_generate | fssh host test_echo | test_consume`
    - `test_generate | ssh localhost test_echo | test_consume`
    - `test_generate | ssh host test_echo | test_consume`

Dependencies:
- `libevent2` (http://libevent.org/)
- `LTTng` (https://lttng.org/)
