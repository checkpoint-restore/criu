package org.criu.java.tests;

import java.io.*;
import java.net.Socket;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.StandardOpenOption;
import java.util.logging.Level;
import java.util.logging.Logger;

class SocketsClient {
	static String TESTNAME = "SocketsClient";

	public static void main(String[] args) {
		MappedByteBuffer socketMappedBuffer = null;
		FileChannel channel;
		Socket socket = null;
		Logger logger = null;
		String msg1 = "Ch@ckM@$$@Ge!1", msg2 = "cH@C!m$SG!!2",
				readMssg, msg3 = "@Ft@rCPM$$g3", msg4 = "Aft@rCPM$$g4";
		String parentTestName, portArg;
		int port;

		try {
			parentTestName = args[0];
			portArg = args[1];
			port = Integer.parseInt(portArg);

			/*
			 * Socket Mapped Buffer to communicate between server process, client process and the calling parent process.
			 */
			File socketfile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + parentTestName + "/SocketsFile");
			channel = FileChannel.open(socketfile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			socketMappedBuffer = channel.map(MapMode.READ_WRITE, 0, Helper.MAPPED_REGION_SIZE);
			channel.close();

			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);
			SocketHelper.init(TESTNAME, parentTestName, logger);

			logger.log(Level.INFO, "Begin");
			logger.log(Level.INFO, "Parent name: " + parentTestName);

			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_INIT && socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != SocketHelper.STATE_LISTEN) {
				logger.log(Level.SEVERE, "Error: Socket-buffer not in expected Init state");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
			}
			logger.log(Level.INFO, "Client socket sending req to server at IP: 127.0.0.1 port:" + port);

			/*
			 * Ensure client does not try to connect to port before server has bound itself.
			 */
			while (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_INIT) {
				;
			}
			/*
			 * Socket Buffer should be put in SocketHelper.STATE_LISTEN state by server process, just before
			 * it starts listening for client connections.
			 */
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != SocketHelper.STATE_LISTEN) {
				logger.log(Level.SEVERE, "Error: Buffer does not contain the expected 'server bound to port and listening' state");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			/*
			 * Ensure server has bound to port
			 */
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
				logger.log(Level.WARNING, "InterruptedException occurred!");
			}

			socket = new Socket(SocketHelper.IP_ADDRESS, port);

			PrintStream out = new PrintStream(socket.getOutputStream());
			BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));

			logger.log(Level.INFO, "Sending message to server " + msg1);
			out.println(msg1);

			readMssg = br.readLine();
			logger.log(Level.INFO, "Message received from server " + readMssg);
			if (!msg2.equals(readMssg)) {
				logger.log(Level.SEVERE, "Error: wrong message received; message expected " + msg2);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
			}

			logger.log(Level.INFO, "Sending message to server " + msg3);
			out.println(msg3);

			readMssg = br.readLine();
			logger.log(Level.INFO, "Message received from server " + readMssg);
			if (!msg4.equals(readMssg)) {
				logger.log(Level.SEVERE, "Error: wrong message received; message expected " + msg4);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			socket.close();
			/*
			 * Wait for server process to end and then check whether it ended successfully or not
			 * If it has finished properly the socketMappedBuffer will contain SocketHelper.STATE_SUCCESS
			 */
			logger.log(Level.INFO, "Waiting for server process to end....");
			while (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_RESTORE) {
				;
			}
			/*
			 * Check the server process has ended successfully, if it was a success put Mapped Buffer to pass state, else to failed state
			 */
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == SocketHelper.STATE_SUCCESS) {
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_PASS);
			} else {
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}
			logger.log(Level.INFO, "Test ends");

		} catch (Exception exception) {
			if (null != logger) {
				StringWriter writer = new StringWriter();
				PrintWriter printWriter = new PrintWriter(writer);
				exception.printStackTrace(printWriter);
				logger.log(Level.SEVERE, "Exception occured:" + exception);
				logger.log(Level.FINE, writer.toString());
			}

			if (socketMappedBuffer != null) {
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}
		}
	}
}
