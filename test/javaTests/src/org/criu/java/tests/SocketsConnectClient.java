package org.criu.java.tests;

import java.io.*;
import java.net.Socket;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.StandardOpenOption;
import java.util.logging.Level;
import java.util.logging.Logger;

class SocketsConnectClient {
	static String TESTNAME = "SocketsConnectClient";

	public static void main(String[] args) {
		MappedByteBuffer socketMappedBuffer = null;
		FileChannel channel;
		Socket socket = null;
		String parentTestName, portArg;
		int port;
		Logger logger = null;
		try {
			parentTestName = args[0];
			portArg = args[1];
			port = Integer.parseInt(portArg);

			String msg1 = "Ch@ckM@$$@Ge!1", msg2 = "cH@C!m$SG!!2",
					readMssg, msg3 = "@Ft@rCPM$$g3", msg4 = "Aft@rCPM$$g4";

			/*
			 * Socket Mapped Buffer to communicate between server process, client process and the calling parent process.
			 */
			File socketfile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + parentTestName + "/SocketsConnectFile");
			channel = FileChannel.open(socketfile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE);
			socketMappedBuffer = channel.map(MapMode.READ_WRITE, 0, Helper.MAPPED_REGION_SIZE);
			channel.close();

			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);
			SocketHelper.init(TESTNAME, parentTestName, logger);

			logger.log(Level.INFO, "Begin");
			logger.log(Level.INFO, "Parent name: " + parentTestName);

			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_INIT && socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_CHECKPOINT && socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_RESTORE) {
				logger.log(Level.SEVERE, "Error: Socket-buffer not in expected Init state");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			logger.log(Level.INFO, "Waiting for CR");
			/*
			 * Wait for Checkpoint-Restore to occur
			 */
			while (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_INIT || socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_CHECKPOINT) {
				;
			}
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_RESTORE) {
				logger.log(Level.SEVERE, "Error:Buffer does not contain the expected restored state: " + socketMappedBuffer.getChar(Helper.MAPPED_INDEX));
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}

			logger.log(Level.INFO, "Restored");
			logger.log(Level.INFO, "Client socket sending req to server at IP: 127.0.0.1 port:" + port);

			/*
			 * Server should has have been listening for client connections when it was checkpointed, and it should continue to listen after restore.
			 */
			try {
				socket = new Socket(SocketHelper.IP_ADDRESS, port);
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Exception occurred when connecting to port: " + e);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			PrintStream out = new PrintStream(socket.getOutputStream());
			BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));

			logger.log(Level.INFO, "Sending message to server " + msg1);
			out.println(msg1);

			readMssg = br.readLine();
			logger.log(Level.INFO, "message received from server " + readMssg);
			if (!msg2.equals(readMssg)) {
				logger.log(Level.SEVERE, "wrong message received; Expected " + msg2);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			logger.log(Level.INFO, "Sending message to server " + msg3);
			out.println(msg3);

			readMssg = br.readLine();
			logger.log(Level.INFO, "message received from server " + readMssg);
			if (!msg4.equals(readMssg)) {
				logger.log(Level.SEVERE, "wrong message received; Expected " + msg4);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			socket.close();

			/*
			 * Wait for server process to end.
			 */
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
