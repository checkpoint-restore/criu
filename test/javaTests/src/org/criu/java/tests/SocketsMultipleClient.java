package org.criu.java.tests;

import java.io.*;
import java.net.Socket;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.StandardOpenOption;
import java.util.logging.Level;
import java.util.logging.Logger;

class SocketsMultipleClient {
	static String TESTNAME = "SocketsMultipleClient";

	public static void main(String[] args) {
		MappedByteBuffer socketMappedBuffer = null;
		FileChannel channel;
		String msg1 = "Message1", msg2 = "Message2", readMssg;
		Socket socket1 = null, socket2 = null, socket3 = null, socket4 = null;
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

			logger.log(Level.INFO, "Begin");
			logger.log(Level.INFO, "Parent name: " + parentTestName);

			while (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_INIT) {
				;
			}
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != SocketHelper.STATE_LISTEN) {
				logger.log(Level.SEVERE, "Error: Socket-buffer not in expected state");

			}
			try {
				logger.log(Level.INFO, "client 1 connecting...");
				socket1 = new Socket(SocketHelper.IP_ADDRESS, port);
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Exception when client connects to server: " + e);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
			}
			logger.log(Level.INFO, "Client 1 connected to server successfully");
			PrintStream out1 = new PrintStream(socket1.getOutputStream());
			BufferedReader br1 = new BufferedReader(new InputStreamReader(socket1.getInputStream()));
			logger.log(Level.INFO, "Got input and output streams for socket1");
			try {
				logger.log(Level.INFO, "client 2 connecting...");
				socket2 = new Socket(SocketHelper.IP_ADDRESS, port);
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Exception when client connects to server: " + e);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
			}
			logger.log(Level.INFO, "Client 2 connected to server successfully");
			PrintStream out2 = new PrintStream(socket2.getOutputStream());
			BufferedReader br2 = new BufferedReader(new InputStreamReader(socket2.getInputStream()));
			logger.log(Level.INFO, "Got input and output streams for socket2");

			try {
				logger.log(Level.INFO, "client 3 connecting...");
				socket3 = new Socket(SocketHelper.IP_ADDRESS, port);
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Exception when client connects to server: " + e);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
			}
			logger.log(Level.INFO, "Client 3 connected to server successfully");
			PrintStream out3 = new PrintStream(socket3.getOutputStream());
			BufferedReader br3 = new BufferedReader(new InputStreamReader(socket3.getInputStream()));
			logger.log(Level.INFO, "Got input and output streams for socket3");

			out1.println(msg1);

			readMssg = br1.readLine();
			if (!msg2.equals(readMssg)) {
				logger.log(Level.SEVERE, "wrong message received; Received: " + readMssg);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
			}
			socket1.close();

			out2.println(msg1);

			/*
			 * Wait for Checkpoint-Restore
			 */
			while (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_INIT || socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == SocketHelper.STATE_LISTEN || socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_CHECKPOINT) {
				;
			}
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_RESTORE) {
				logger.log(Level.SEVERE, "Socket-mapped-buffer is not in restored state");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			logger.log(Level.INFO, "Server is Restored!!");

			out3.println(msg1);
			readMssg = br2.readLine();
			if (!msg2.equals(readMssg)) {
				logger.log(Level.SEVERE, "wrong message received by client 2; Received: " + readMssg);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			readMssg = br3.readLine();
			if (!msg2.equals(readMssg)) {
				logger.log(Level.SEVERE, "wrong message received by client 3; Received: " + readMssg);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			socket2.close();
			socket3.close();

			try {
				logger.log(Level.INFO, "client 4 connecting...");
				socket4 = new Socket(SocketHelper.IP_ADDRESS, port);
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Exception when client connects to server: " + e);
			}
			logger.log(Level.INFO, "Client 4 connected to server successfully");
			PrintStream out4 = new PrintStream(socket4.getOutputStream());
			BufferedReader br4 = new BufferedReader(new InputStreamReader(socket4.getInputStream()));
			logger.log(Level.INFO, "Got input and output streams for socket4");

			out4.println(msg1);
			readMssg = br4.readLine();
			if (!msg2.equals(readMssg)) {
				logger.log(Level.SEVERE, "wrong message received by client 4; Received: " + readMssg);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}

			socket4.close();
			/*
			 * Wait for server process to end.
			 */
			while (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_RESTORE) {
				;
			}
			/*
			 * Check the server process has ended successfully, if it was a success put Mapped Buffer to STATE_PASS, else to STATE_FAIL
			 */
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == SocketHelper.STATE_SUCCESS) {
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_PASS);
			} else {
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
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
				System.exit(1);
			}
		}
	}
}
