`fssh` - execute program via SSH, while tolerating TCP connection losses

Implementation is work in progress.

###### Executables:
- `fssh` - `ssh` drop-in replacement, that forks `ssh fssh-fwd` and `fssh-client`
- `fssh-fwd` - volatile process that forks `fssh-daemon`
- `fssh-daemon` - forks and shepherds user-speficied executable, forwards data between executable's standard streams and user-specified zeromq endpoint
- `fssh-client` - forwards data between standard streams and user-specified zeromq endpoint

###### Flow:
- `fssh user@host pgm args...` forks two processes:
	* `ssh -L localhost:32167:localhost:32167 user@host fssh-fwd tcp://localhost:32167 pgm args...` - this process is restarted if it exits
	* `fssh-client tcp://localhost:32167` - `fssh` exits once this process exits
- `fssh-fwd endpoint pgm args...` checks if endpoint exists, and if not, forks `fssh-daemon endpoint pgm args...`.
In any case, it ultimately goes into sleep, allowing `ssh` to do the port forwarding job.

During execution of `pgm`, `fssh`, `fssh-client` and `fssh-daemon` keep running, while `fssh-fwd` might be restarted multiple times due to TCP connection losses.

###### Protocol:
Four types of zeromq messages are defined:
- stdin data (sent from client to daemon): byte `0x00` followed by data, no data means EOF
- stdout data (sent from daemon to client): byte `0x01` followed by data, no data means EOF
- stderr data (sent from daemon to client): byte `0x02` followed by data, no data means EOF
- exit code (sent from client to daemon): byte `0x03` followed by exit code encoded as big-endian `uint32_t`

###### Dependencies:
- `openssh` (http://www.openssh.com/)
- `zeromq` (http://zeromq.org/)
- `LTTng` (http://lttng.org/)
