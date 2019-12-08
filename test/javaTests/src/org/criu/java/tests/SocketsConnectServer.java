package org.criu.java.tests;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.StandardOpenOption;
import java.util.logging.Level;
import java.util.logging.Logger;

class SocketsConnectServer {
	static String TESTNAME = "SocketsConnectServer";

	public static void main(String[] args) {
		MappedByteBuffer socketMappedBuffer = null;
		FileChannel channel;
		Socket socket = null;
		String msg1 = "Ch@ckM@$$@Ge!1", msg2 = "cH@C!m$SG!!2", msg3 = "@Ft@rCPM$$g3",
				msg4 = "Aft@rCPM$$g4", readMssg;
		Logger logger = null;
		String parentTestName, portArg;
		int port;
		try {
			parentTestName = args[0];
			portArg = args[1];
			port = Integer.parseInt(portArg);

			/*
			 * Socket Mapped Buffer to communicate between server process, client process and the calling parent process.
			 */
			File socketfile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + parentTestName + "/SocketsConnectFile");
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
			}

			ServerSocket ser = new ServerSocket(port);
			logger.log(Level.INFO, "Server will be listening on Port: " + port);

			/*
			 * Timeout after 7 sec if client does not connect
			 */
			try {
				ser.setSoTimeout(7 * 1000);

			} catch (SocketException e) {
				logger.log(Level.SEVERE, "Cannot set timeout!");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}
			logger.log(Level.INFO, "Waiting for client to connect");
			logger.log(Level.INFO, "Going to checkpoint");

			try {
				if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_FAIL || socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_END) {
					ser.close();
					System.exit(1);
				}
				/*
				 * Checkpoint when server is listening for connections, and no client has connected to the server.
				 */
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_CHECKPOINT);
				socket = ser.accept();
				SocketHelper.socketWaitForRestore(socketMappedBuffer, logger);

			} catch (Exception e) {
				logger.log(Level.SEVERE, "Timed out while waiting for client to connect\n" + e);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}

			if (!ser.isBound()) {
				logger.log(Level.SEVERE, "Server is not bound to a port");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			if (ser.getLocalPort() != port) {
				logger.log(Level.SEVERE, "Server is not listening on correct port");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintStream outstream = new PrintStream(socket.getOutputStream());

			readMssg = br.readLine();
			logger.log(Level.INFO, "Read message 1: " + readMssg);
			if (!msg1.equals(readMssg)) {
				logger.log(Level.SEVERE, "Message 1 received was wrong,received: " + readMssg + " expected: " + msg1);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			logger.log(Level.INFO, "Sending message: " + msg2);
			outstream.println(msg2);

			readMssg = br.readLine();
			logger.log(Level.INFO, "Read message 3: " + readMssg);

			if (!msg3.equals(readMssg)) {
				logger.log(Level.SEVERE, "Message 3 received was wrong, received: " + readMssg + " expected: " + msg3);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			outstream.println(msg4);
			logger.log(Level.INFO, "Sent message 4 " + msg4);

			socket.close();

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
