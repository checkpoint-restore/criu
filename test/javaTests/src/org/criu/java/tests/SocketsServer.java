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

class SocketsServer {
	static String TESTNAME = "SocketsServer";

	public static void main(String[] args) {
		MappedByteBuffer socketMappedBuffer = null;
		String msg1 = "Ch@ckM@$$@Ge!1", msg2 = "cH@C!m$SG!!2",
				msg3 = "@Ft@rCPM$$g3", msg4 = "Aft@rCPM$$g4", readMssg;
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
			File socketfile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + parentTestName + "/SocketsFile");
			channel = FileChannel.open(socketfile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			socketMappedBuffer = channel.map(MapMode.READ_WRITE, 0, Helper.MAPPED_REGION_SIZE);
			channel.close();

			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);

			SocketHelper.init(TESTNAME, parentTestName, logger);
			logger.log(Level.INFO, "Begin");
			logger.log(Level.INFO, "Parent name: " + parentTestName);

			RuntimeMXBean bean = ManagementFactory.getRuntimeMXBean();
			String pid = bean.getName();
			SocketHelper.writePid(parentTestName, pid);

			logger.log(Level.INFO, "Socket buffer mapped");

			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_INIT) {
				logger.log(Level.SEVERE, "Socket-buffer not in expected Init state");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
			}

			ServerSocket s = new ServerSocket(port);
			logger.log(Level.INFO, "Server will be listening on Port " + port);

			/*
			 * Timeout after 5 second if client does not connect
			 */
			s.setSoTimeout(5 * 1000);
			logger.log(Level.INFO, "Waiting for client to connect");
			Socket socket = null;
			try {
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, SocketHelper.STATE_LISTEN);
				socket = s.accept();
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Timed out while waiting for client to connect");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
			}
			BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintStream outstream = new PrintStream(socket.getOutputStream());

			readMssg = br.readLine();
			logger.log(Level.INFO, "Read message 1: " + readMssg);
			if (!msg1.equals(readMssg)) {
				logger.log(Level.SEVERE, "Message 1 received was wrong:rec " + readMssg + " expected: " + msg1);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
			}

			logger.log(Level.INFO, "Sending message: " + msg2);
			outstream.println(msg2);

			logger.log(Level.INFO, "Going to checkpoint");
			/*
			 * Put socket Mapped Buffer to 'to be checkpointed' state and wait for restore
			 */
			socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_CHECKPOINT);
			SocketHelper.socketWaitForRestore(socketMappedBuffer, logger);

			if (!s.isBound()) {
				logger.log(Level.SEVERE, "Server is not bound to a port");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			if (s.getLocalPort() != port) {
				logger.log(Level.SEVERE, "Server is not listening on correct port");
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			readMssg = br.readLine();
			logger.log(Level.INFO, "Read message 3: " + readMssg);

			if (!msg3.equals(readMssg)) {
				logger.log(Level.SEVERE, "Message 3 received was wrong:rec " + readMssg + " expected: " + msg3);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				socket.close();
				System.exit(1);
			}

			outstream.println(msg4);
			logger.log(Level.INFO, "Sent message 4 " + msg4);

			/*
			 * Put Socket-MappedBuffer to state SocketHelper.STATE_SUCCESS telling the server process has ended successfully.
			 */
			socket.close();
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
