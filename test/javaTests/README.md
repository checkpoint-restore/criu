# JavaTests

Java Functional tests checks the Java File based APIs and Memory mapping APIs by placing the process in various states before checkpointing and validates if these resources are still accessible after restore. It also validates if the file contents are in expected states.

Tests are to be run by a user having following capabilities:  
CAP_DAC_OVERRIDE  
CAP_CHOWN  
CAP_SETPCAP  
CAP_SETGID  
CAP_AUDIT_CONTROL  
CAP_DAC_READ_SEARCH  
CAP_NET_ADMIN  
CAP_SYS_ADMIN  
CAP_SYS_CHROOT  
CAP_SYS_PTRACE  
CAP_FOWNER  
CAP_KILL  
CAP_FSETID  
CAP_SYS_RESOURCE  
CAP_SETUID

## File-based Java APIs

Here we test the File-Based Java APIs by checkpointing the application in the following scenarios and verifying the contents of the file after restore:
- Reading and writing in the same file. (FileRead.java)

### Prerequisites for running the tests:
- Maven

### To run the tests:
- In the javaTests folder run the command ```sudo mvn test```
- To keep the img files and logs from previous failures, between different runs of the test, use the ```-DneverCleanFailures=true ``` option in the maven command
as ```sudo mvn -DneverCleanFailures=true test```
