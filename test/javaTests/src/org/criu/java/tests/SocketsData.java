package org.criu.java.tests;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.StandardOpenOption;
import java.util.logging.Level;
import java.util.logging.Logger;

class SocketsData {
	static String TESTNAME = "SocketsData";

	/**
	 * Runs the server and client processes, checkpoints the client process when its in the middle of data transfer
	 *
	 * @param args Not used
	 */
	public static void main(String[] args) {
		MappedByteBuffer b = null, socketMappedBuffer = null;
		FileChannel channel;
		String pid;
		Logger logger = null;
		String port = "49200";
		try {
			/*
			 * Mapped buffer 'b' to communicate between CheckpointRestore.java and this process.
			 */
			File f = new File(Helper.MEMORY_MAPPED_FILE_NAME);
			channel = FileChannel.open(f.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			b = channel.map(MapMode.READ_WRITE, 0, Helper.MAPPED_REGION_SIZE);
			channel.close();

			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);

			RuntimeMXBean bean = ManagementFactory.getRuntimeMXBean();
			pid = bean.getName();
			Helper.init(TESTNAME, pid, logger);
			logger.log(Level.INFO, "Test init done; pid written to pid file; beginning with test");

			if (b.getChar(Helper.MAPPED_INDEX) != Helper.STATE_INIT) {
				logger.log(Level.SEVERE, "Error: Error in memory mapping, test is not in init state");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}

			/*
			 * Socket Mapped Buffer to communicate between server process, client process and this process.
			 */
			logger.log(Level.INFO, "Creating socketbufferfile and setting the init value of buffer");
			File socketfile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + TESTNAME + "/SocketsDataFile");
			channel = FileChannel.open(socketfile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			socketMappedBuffer = channel.map(MapMode.READ_WRITE, 0, Helper.MAPPED_REGION_SIZE);
			channel.close();

			/*
			 * Set socketMappedBuffer to init state.
			 */
			socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_INIT);
			logger.log(Level.INFO, "Starting server and client process");
			ProcessBuilder builder = new ProcessBuilder("java", "-cp", "target/classes", Helper.PACKAGE_NAME + "." + "SocketsDataServer", TESTNAME, port);
			Process serverProcess = builder.start();
			builder = new ProcessBuilder("java", "-cp", "target/classes", Helper.PACKAGE_NAME + "." + "SocketsDataClient", TESTNAME, port);
			Process clientProcess = builder.start();

			while (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_INIT || socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == SocketHelper.STATE_LISTEN) {
				;
			}
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_END) {
				logger.log(Level.SEVERE, "Killing the server process and client process");
				logger.log(Level.SEVERE, "Some error took place in the client or server process: check their log for details");
				serverProcess.destroy();
				clientProcess.destroy();
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_FAIL) {
				logger.log(Level.SEVERE, "Killing the server process and client process");
				logger.log(Level.SEVERE, "Exception occured in the client or server process: check their log for details");
				serverProcess.destroy();
				clientProcess.destroy();
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) != Helper.STATE_CHECKPOINT) {
				logger.log(Level.SEVERE, "Killing the server process and client process");
				logger.log(Level.SEVERE, "State is not the expected 'to be checkpointed' state");
				serverProcess.destroy();
				clientProcess.destroy();
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_CHECKPOINT) {
				logger.log(Level.INFO, "Going to checkpoint client process");
				try {
					Thread.sleep(10);
				} catch (InterruptedException e) {
					logger.log(Level.WARNING, "Thread was interrupted");
				}
				SocketHelper.checkpointAndWait(b, logger, serverProcess, clientProcess);
				socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_RESTORE);
				logger.log(Level.INFO, "Process has been restored!");
			}

			while (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_RESTORE) {
				;
			}
			char bufchar = socketMappedBuffer.getChar(Helper.MAPPED_INDEX);
			if (bufchar != Helper.STATE_FAIL && bufchar != Helper.STATE_PASS && bufchar != SocketHelper.STATE_SUCCESS) {
				logger.log(Level.SEVERE, "Received wrong message from the child process: not the expected finish message");
				logger.log(Level.SEVERE, "Check their log files for more details");
				serverProcess.destroy();
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_FAIL || socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_END) {
				logger.log(Level.SEVERE, "Error in the client or server process: check their log for details");
				serverProcess.destroy();
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			while (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == SocketHelper.STATE_SUCCESS) {
				;
			}

			/*
			 * Client process puts socketMappedBuffer to STATE_PASS if the test passed.
			 */
			if (socketMappedBuffer.getChar(Helper.MAPPED_INDEX) == Helper.STATE_PASS) {
				logger.log(Level.INFO, Helper.PASS_MESSAGE);
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_PASS);
			} else {
				logger.log(Level.INFO, "Did not receive pass message from the client process");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}

		} catch (Exception e) {
			if (null != logger) {
				StringWriter writer = new StringWriter();
				PrintWriter printWriter = new PrintWriter(writer);
				e.printStackTrace(printWriter);
				logger.log(Level.SEVERE, "Exception occured:" + e);
				logger.log(Level.FINE, writer.toString());
			}
			if (b != null) {
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}
			System.exit(5);
		}
	}
}
