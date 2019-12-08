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
- Read from a file and write its content to another file. (ReadWrite.java)
- Reading from multiple files and writing their content to another file. (MultipleFileRead)
- Reading from a file and writing its content to multiple files. (MultipleFileWrite)

## Memory mapping Java APIs

Here we test the Memory Mapping APIs by checkpointing the application in following scenario and verifying the contents after restore:
- Memory-mapping a file and writing its content to another file. (MemoryMappings.java)  

## Socket-based Java APIs

Here we test the Socket-based API's by checkpointing the application in the following scenario and verifying the state after restore:  
- Checkpointing the server process in the middle of data transfer. (Sockets.java)  
- Checkpointing the server process after it has bound to a port but is not listening for client connections. (SocketListen.java)  
- Checkpointing the server process while it is listening for client connections, and no client has connected yet. (SocketConnect.java)  
- Checkpointing the server process when it has multiple clients in multiple states connected to it. (SocketMultiple.java)  
- Checkpointing the client process in the middle of data transfer. (SocketsData.java)  

### Prerequisites for running the tests:
- Maven

### To run the tests:
- In the javaTests folder run the command ```sudo mvn test```
- To keep the img files and logs from previous failures, between different runs of the test, use the ```-DneverCleanFailures=true ``` option in the maven command
as ```sudo mvn -DneverCleanFailures=true test```
