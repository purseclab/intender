# Agents for Intender
## Test Agent
The `test_agent` operates and manages an emulated network based on `mininet`.
Before Intender starts fuzzing tests, Intender executes `test_agent` with a topology information in given scenario(s).

You can execute `test_agent` independently as follows:
### Start Test Agent
```shell
$ cd ./agents
$ sudo python3 ./test-agent.py start -t fattree -s 2 -c [ONOS_IP]
```
### Stop Test Agent
```shell
$ sudo python3 ./test-agent.py stop
```

## Application Agent
Intender can request intent operations with two options: REST API or **Application API**.

To use Application API:
* Run `intender-agent` app alongside ONOS controller.
* Add `IntentInterface intentInterface = new ONOSAgentInterface();` in `src/main/java/edu/purdue/cs/pursec/ifuzzer/IFuzzer.java`

### Deploy Intender AppAgent

1. Build IntenderAgent
```shell
$ cd ./agents/onos-2.5.1/intender-agent
$ mvn clean install
```
2. Reinstall IntenderAgent ONOS application
```shell
$ onos-app [ONOS_IP] reinstall! target/intender-agent-1.0-SNAPSHOT.oar
```


## AFL Agent
The `afl-agent` proxy transfers a new random input from AFL to Intender via inter-process communication (IPC).
### Requirement
1. Download and build AFL
```shell
$ git clone https://github.com/google/AFL && (cd AFL && make)
```
2. Set `AFL_DIR` environment variable for `afl-agent` to find the location of AFL
```shell
$ export AFL_DIR=$(pwd)/AFL
```

### Usage
1. Configure `CONFIG_FUZZING_INTENT_GUIDANCE`
```shell
$ cd ibn-fuzzer
$ nano src/main/java/edu/purdue/cs/pursec/ifuzzer/api/ConfigConstants.java
public static final String CONFIG_FUZZING_INTENT_GUIDANCE = "AFLIntentGuidance";
```
2. Execute Intender and start fuzzing
```shell
$ sudo -E java -jar target/IFuzzer-jar-with-dependencies.jar
intender> fuzz -t PT1H [file or directory]

# wait until the first run succeeds
```
3. In another terminal, execute `afl-fuzz-local`
```shell
$ cd agents/afl-agent
# Repeat the following command until AFL starts running
$ sudo -E ./afl-fuzz-local
```