package org.criu.java.tests;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.StandardOpenOption;
import java.util.logging.Level;
import java.util.logging.Logger;

class SocketsDataServer {
	static String TESTNAME = "SocketsDataServer";

	public static void main(String[] args) {
		MappedByteBuffer socketMappedBuffer = null;
		FileChannel channel;
		String parentTestName, portArg;
		int port;
		Socket socket = null;
		Logger logger = null;
		String msg1 = "Ch@ckM@$$@Ge!1", msg2 = "cH@C!m$SG!!2",
				msg3 = "@Ft@rCPM$$g3", msg4 = "Aft@rCPM$$g4", readMssg;

		try {
			parentTestName = args[0];
			portArg = args[1];
			port = Integer.parseInt(portArg);

			/*
			 * Socket Mapped Buffer to communicate between server process, client process and the calling parent process.
			 */
			File socketfile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + parentTestName + "/SocketsDataFile");
			channel = FileChannel.open(socketfile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			socketMappedBuffer = channel.map(MapMode.READ_WRITE, 0, Helper.MAPPED_REGION_SIZE);
			channel.close();

			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);
			SocketHelper.init(TESTNAME, parentTestName, logger);

			logger.log(Level.INFO, "Begin");
			logger.log(Level.INFO, "Parent name: " + parentTestName);
			logger.log(Level.INFO, "socket buffer connection opened");

			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_INIT) {
				logger.log(Level.SEVERE, "Socket-buffer not in expected Init state");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}

			ServerSocket s = new ServerSocket(port);
			logger.log(Level.INFO, "Server will be listening on Port " + port);

			/*
			 * Wait for 7 seconds for client to connect, else throw a timeout exception
			 */
			try {
				s.setSoTimeout(7 * 1000);

			} catch (SocketException e) {
				logger.log(Level.SEVERE, "cannot set timeout");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}

			logger.log(Level.INFO, "Waiting for client to connect");
			/*
			 * Put Socket Mapped Buffer to SocketHelper.STATE_LISTEN state - server has bound to port and
			 * begin listening for connections.
			 */
			socketMappedBuffer.putChar(Helper.MAPPED_INDEX, SocketHelper.STATE_LISTEN);
			socket = s.accept();
			BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintStream outstream = new PrintStream(socket.getOutputStream());

			readMssg = br.readLine();
			logger.log(Level.INFO, "Read message 1: " + readMssg);

			if (!msg1.equals(readMssg)) {
				logger.log(Level.SEVERE, "Message 1 received was wrong:rec " + readMssg + " expected: " + msg1);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			logger.log(Level.INFO, "Sending message: " + msg2);
			outstream.println(msg2);

			readMssg = br.readLine();
			logger.log(Level.INFO, "Read message 3: " + readMssg);

			if (!msg3.equals(readMssg)) {
				logger.log(Level.SEVERE, "Message 3 received was wrong:rec " + readMssg + " expected: " + msg3);
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
