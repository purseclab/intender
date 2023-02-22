# Intender: Intent-Based Networking (IBN) Fuzzer

Intender is the first black-box fuzzing framework for the Intent-Based Networking.
You can discover the reasoning behind Intender by reading the paper published at USENIX Security 2023 (to be appeared).

## Getting started
Intender has been thoroughly tested on a machine running Ubuntu 18.04 and is known to work seamlessly on this platform.

### Requirements
To build and test Intender, you need to install the following software packages:
* Maven
* JDK 11
* Python3
* Docker (optional)

Following python packages are necessary:
```shell
$ pip3 install mininet flask scapy thrift netaddr psutil
```

For the SDN environment, you need to install packages or run docker containers:
* ONOS 2.5.1
* RabbitMQ

To execute the test-agent in Intender, you need following software to be installed on machine:
* Open vSwitch 2.14.0
* Mininet 2.2.2

To test other fuzzing tools, you need to install following software:
* AFL
* Jazzer


### Installation
```shell
$ mvn clean install
```

### Usage
Before running Intender, you must run `ONOS` and `RabbitMQ` for Intender to communicate with them.
```shell
$ sudo -E java -jar target/IFuzzer-jar-with-dependencies.jar
intender> help
```

### Examples
Intender runs fuzz testing with seed file(s) under `scenario` directory.

To run seed scenario(s) once:
```shell
intender> fuzz [file or directory]
```
To run fuzz input scenario(s) with a specific number of times:
```shell
intender> fuzz -f 1000 [file or directory]
```

To run fuzz input scenario(s) over a designated period of time (e.g., 1 hour):
```shell
intender> fuzz -t PT1H [file or directory]
```

If any error occurs during the fuzzing test,
a record of the error scenario will be saved in the `scenario/failure` directory with a file name that includes a timestamp.

To replay the error scenario(s):
```shell
# -i: interactive mode
intender> replay [-i] 20XXXXXX-XXXXXX-XXX.json
```

### Cleanup
After running Intender, you need to stop the `test-agent` daemon:
```shell
$ sudo python3 ./agents/test-agent.py stop
```

## Advanced Usage
### Build ONOS from source for Intender to get code coverage
Intender basically leverages a black-box fuzzing guidance, Intent-State Transition Guidance (ISTG).
To enable code-coverage guidance (CCG), you need to run `jacocoagent` with ONOS controller in local.
(Docker with this feature will be supported later.)

To build ONOS from source and follow the steps, the following packages are required:
* Bazel 3.7.2
* curl
* zip
* unzip

Also, Intender must find Java compiled class files of ONOS.
Intender searches the directory specified by the environment variable `ONOS_BIN_PATH`.
The most common way to get started with Intender and a local ONOS is as follows:


1. Clone the code from the ONOS Gerrit repository and checkout the tag that was tested with Intender.
```shell
$ git clone https://github.com/opennetworkinglab/onos.git && cd onos && git checkout 2.5.1
```
2. Set environment variables. 
Note that this is a one-time setup, and you only need to run this command once.
```shell
$ cat << EOF >> ~/.bashrc
export ONOS_ROOT="`pwd`"
source $ONOS_ROOT/tools/dev/bash_profile
export ONOS_BIN_PATH="`bazel info bazel-bin`"
EOF
$ . ~/.bashrc
```
3. Download `jacocoagent.jar`.
```shell
$ cd $ONOS_ROOT
$ wget https://github.com/jacoco/jacoco/releases/download/v0.8.6/jacoco-0.8.6.zip
$ unzip jacoco-0.8.6.zip -d jacoco-0.8.6
```
4. Set `jacocoagent.jar` as a `JAVA_OPTS` in ONOS.
```shell
$ nano tools/package/bin/onos-service

# Add the following line below the line for JAVA_OPTS
export JAVA_OPTS="${JAVA_OPTS} -javaagent:${ONOS_ROOT}/jacoco-0.8.6/lib/jacocoagent.jar=output=tcpserver"
```

5. Build ONOS with Bazel
```shell
$ bazel build onos
```

### Deploy Intender AppAgent

1. Build IntenderAgent.
```shell
$ cd ./agents/onos-2.5.1/intender-agent
$ mvn clean install
```
2. Reinstall IntenderAgent ONOS application
```shell
$ onos-app [ONOS IP] reinstall! target/intender-agent-1.0-SNAPSHOT.oar
```