`fssh` - execute program via SSH, surviving TCP connection losses

###### Usage:
`fssh [SSH_OPTIONS] [USER@]HOSTNAME PGM [ARGS]...`

###### Usage with Jenkins:
`fssh` is useful in situations when Jenkins master frequently disconnects from Jenkins slave due to network issues.
Normally this results in termination of running builds, but `fssh` can save the day!
Install `fssh` on Jenkins master and Jenkins slave, and use launch method "Launch slave via execution of command on the Master" with the following command:
`fssh user@jenkins-slave.local sh -c "\"wget --output-document=/home/user/jenkins/slave.jar http://jenkins-master.local/jnlpJars/slave.jar </dev/null >/dev/null 2>/dev/null && cd /home/user/jenkins && java -jar slave.jar\""`

###### Executables:
- `fssh` - `ssh` drop-in replacement, that forks `ssh fssh-fwd` and `fssh-client`
- `fssh-fwd` - forks `fssh-daemon`, forwards data between stdin/stdout and daemon's unix socket
- `fssh-daemon` - forks and shepherds user-speficied executable,
  forwards data between executable's standard streams and user-specified zeromq endpoint
- `fssh-client` - forwards data between standard streams and user-specified zeromq endpoint

###### Flow:
- `fssh user@host pgm args...` forks two processes:
	* `ssh user@host fssh-fwd ipc://tmp/fssh-server-XXX pgm args...  <>/tmp/fssh-client-XXX` - if this process exits, it is restarted
	* `fssh-client ipc://tmp/fssh-client-XXX` - `fssh` exits once this process exits
- `fssh-fwd ipc://tmp/fssh-server-XXX pgm args...` forks `fssh-daemon ipc://tmp/fssh-server-XXX pgm args...`
  and forwards data between stdin/stdout and `/tmp/fssh-server-XXX`.
  If another instance of `fssh-daemon` is already using `/tmp/fssh-server-XXX`, the forked one exits.

During `pgm` execution `fssh`, `fssh-client` and `fssh-daemon` keep running,
while `fssh-fwd` might be restarted multiple times due to TCP connection losses.

###### Protocol:
Four types of zeromq messages are defined:
- stdin data (sent from client to daemon): byte `0x00` followed by data, no data means EOF
- stdout data (sent from daemon to client): byte `0x01` followed by data, no data means EOF
- stderr data (sent from daemon to client): byte `0x02` followed by data, no data means EOF
- exit code (sent from daemon to client): byte `0x03` followed by exit code encoded as big-endian `uint32_t`

###### Dependencies:
- `openssh` (required, http://www.openssh.com/)
- `socat` (required, http://www.dest-unreach.org/socat/)
- `zeromq` (required, http://zeromq.org/)
- `LTTng` (optional, http://lttng.org/)
