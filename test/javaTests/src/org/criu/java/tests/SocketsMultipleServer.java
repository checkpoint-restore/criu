package org.criu.java.tests;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.StandardOpenOption;
import java.util.logging.Level;
import java.util.logging.Logger;

class SocketsMultipleServer {
	static String TESTNAME = "SocketsMultipleServer";

	public static void main(String[] args) {
		MappedByteBuffer socketMappedBuffer = null;
		FileChannel channel;
		String parentTestName, portArg;
		int port;
		Logger logger = null;
		try {
			parentTestName = args[0];
			portArg = args[1];
			port = Integer.parseInt(portArg);

			/*
			 * Socket Mapped Buffer to communicate between server process, client process and the calling parent process.
			 */
			File socketfile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + parentTestName + "/SocketsMultipleFile");
			channel = FileChannel.open(socketfile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			socketMappedBuffer = channel.map(MapMode.READ_WRITE, 0, Helper.MAPPED_REGION_SIZE);
			channel.close();

			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);
			SocketHelper.init(TESTNAME, parentTestName, logger);

			RuntimeMXBean bean = ManagementFactory.getRuntimeMXBean();
			String pid = bean.getName();
			SocketHelper.writePid(parentTestName, pid);

			logger.log(Level.INFO, "Begin");
			logger.log(Level.INFO, "Parent name: " + parentTestName);
			logger.log(Level.INFO, "Server pid: " + pid);
			logger.log(Level.INFO, "socket buffer connection opened");

			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_INIT) {
				logger.log(Level.SEVERE, "Socket-buffer not in expected Init state");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}

			/*
			 * The array indexes 3, 5, 7 and 9 will map the state of client 1, 2, 3 and 4.
			 * Set these array indexes to init state.
			 */

			socketMappedBuffer.putChar(3, Helper.STATE_INIT);
			socketMappedBuffer.putChar(5, Helper.STATE_INIT);
			socketMappedBuffer.putChar(7, Helper.STATE_INIT);
			socketMappedBuffer.putChar(9, Helper.STATE_INIT);

			ServerSocket s = new ServerSocket(port);
			logger.log(Level.INFO, "Server will be listening on Port " + port);

			Socket[] sockets = new Socket[4];

			/*
			 * Set the SocketMappedBuffer to S state-server will be listening for connections
			 */
			socketMappedBuffer.putChar(Helper.MAPPED_INDEX, SocketHelper.STATE_LISTEN);

			for (int i = 1; i <= 4; i++) {
				sockets[i - 1] = s.accept();
				ServerThread serverThread = new ServerThread(sockets[i - 1], "s-socket " + i, 2 * i + 1, logger, socketMappedBuffer);
				serverThread.start();
				if (i == 3) {
					logger.log(Level.INFO, "Connected to client: 3");
					/*
					 * Client 3 has connected, wait for thread 1 to finish and then checkpoint.
					 */
					while (socketMappedBuffer.getChar(3) != Helper.STATE_FAIL && socketMappedBuffer.getChar(3) != Helper.STATE_PASS) {
						;
					}
					logger.log(Level.INFO, "Going to checkpoint");
					socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_CHECKPOINT);
					SocketHelper.socketWaitForRestore(socketMappedBuffer, logger);
				}
			}

			/*
			 * Loop while any of the 4 thread is running
			 */
			while (socketMappedBuffer.getChar(3) == Helper.STATE_INIT || socketMappedBuffer.getChar(5) == Helper.STATE_INIT
					|| socketMappedBuffer.getChar(7) == Helper.STATE_INIT || socketMappedBuffer.getChar(9) == Helper.STATE_INIT) {
				;
			}

			/*
			 * Check Socket Mapped Buffer for a thread that failed
			 */
			for (int i = 1; i <= 4; i++) {
				if (socketMappedBuffer.getChar(i * 2 + 1) == Helper.STATE_FAIL) {
					logger.log(Level.SEVERE, "Error in thread connected to client " + i);
					socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
					System.exit(1);
				}
			}

			/*
			 * Check the 1st Socket is closed
			 */
			if (!sockets[0].isClosed()) {
				logger.log(Level.SEVERE, "socket 1 is not closed");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			logger.log(Level.INFO, "Socket 1 is in expected closed state: " + sockets[0].isClosed());

			/*
			 * Check all threads are in expected pass state
			 */
			for (int i = 1; i <= 4; i++) {
				if (socketMappedBuffer.getChar(i * 2 + 1) != Helper.STATE_PASS) {
					logger.log(Level.SEVERE, "Unexpected State of buffer: " + socketMappedBuffer.getChar(i * 2 + 1) + ", client: " + i);
					socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
					System.exit(1);
				}
			}
			logger.log(Level.INFO, "Done");

			/*
			 * Put Socket-MappedBuffer to state SocketHelper.STATE_SUCCESS telling the server process has ended successfully.
			 */
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_FAIL || socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_END) {
				System.exit(1);
			} else {
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, SocketHelper.STATE_SUCCESS);
			}

		} catch (Exception exception) {
			if (null != logger) {
				StringWriter writer = new StringWriter();
				PrintWriter printWriter = new PrintWriter(writer);
				exception.printStackTrace(printWriter);
				logger.log(Level.SEVERE, "Exception occurred:" + exception);
				logger.log(Level.FINE, writer.toString());
			}

			if (socketMappedBuffer != null) {
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}
		}
	}
}

class ServerThread extends Thread {
	Socket socket = null;
	String name;
	int num;
	MappedByteBuffer socketMappedBuffer;
	Logger logger;

	ServerThread(Socket socket, String name, int num, Logger logger, MappedByteBuffer socketMappedBuffer) {
		this.socket = socket;
		this.name = name;
		this.logger = logger;
		this.num = num;
		this.socketMappedBuffer = socketMappedBuffer;
	}

	public void run() {
		try {
			String readMssg, msg1 = "Message1", msg2 = "Message2";
			BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintStream out = new PrintStream(socket.getOutputStream());
			readMssg = br.readLine();
			if (!msg1.equals(readMssg)) {
				logger.log(Level.SEVERE, "Message read by thread " + name + " was not 'Message1', received Message: " + readMssg);
				socket.close();
				socketMappedBuffer.putChar(num, Helper.STATE_FAIL);
			} else {
				logger.log(Level.INFO, name + " received correct message");
				out.println(msg2);
				logger.log(Level.INFO, name + " has sent message");
				socket.close();
				socketMappedBuffer.putChar(num, Helper.STATE_PASS);
			}

		} catch (Exception exception) {
			if (null != logger) {
				StringWriter writer = new StringWriter();
				PrintWriter printWriter = new PrintWriter(writer);
				exception.printStackTrace(printWriter);
				logger.log(Level.SEVERE, "Exception occurred in thread :" + name + " " + exception);
				logger.log(Level.FINE, writer.toString());
			}

			try {
				if (socket != null) {
					socket.close();
				}
			} catch (IOException e) {
				;
			}

			/*
			 * If exception occurs fail the thread
			 */
			socketMappedBuffer.putChar(num, Helper.STATE_FAIL);
		}
	}
}
