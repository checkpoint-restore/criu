package org.criu.java.tests;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

class SocketHelper {

	static char STATE_LISTEN = 'S';
	static char STATE_SUCCESS = 'Z';
	static String IP_ADDRESS = "127.0.0.1";

	/**
	 * Creates a new log file, for the logger to log in.
	 *
	 * @param testName       Name of the server or client program
	 * @param parentTestName Name of the test
	 * @param logger
	 * @throws IOException
	 */
	static void init(String testName, String parentTestName, Logger logger) throws IOException {
		FileHandler handler = new FileHandler(Helper.OUTPUT_FOLDER_NAME + "/" + parentTestName + "/" + testName + ".log", false);
		handler.setFormatter(new SimpleFormatter());
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
		logger.setLevel(Level.FINE);
	}

	/**
	 * Writes pid of the process to be checkpointed in the file
	 *
	 * @param parentTestName Name of the test
	 * @param pid            Pid of the process to be checkpointed
	 * @throws IOException
	 */
	static void writePid(String parentTestName, String pid) throws IOException {
		File pidfile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + parentTestName + "/" + parentTestName + Helper.PID_APPEND);
		BufferedWriter pidwriter = new BufferedWriter(new FileWriter(pidfile));
		/*
		 * Overwriting pid to be checkpointed
		 */
		pidwriter.write(pid + "\n");
		pidwriter.close();
	}

	/**
	 * Waits for the MappedByteBuffer to change state from STATE_CHECKPOINT to STATE_RESTORE
	 *
	 * @param socketMappedBuffer MappedByteBuffer between the client, server and the controller process.
	 * @param logger
	 */
	static void socketWaitForRestore(MappedByteBuffer socketMappedBuffer, Logger logger) {
		while (Helper.STATE_CHECKPOINT == socketMappedBuffer.getChar(Helper.MAPPED_INDEX)) {
			;
		}
		if (Helper.STATE_RESTORE != socketMappedBuffer.getChar(Helper.MAPPED_INDEX)) {
			logger.log(Level.SEVERE, "Server socket was not in expected restore state " + socketMappedBuffer.getChar(Helper.MAPPED_INDEX));
			socketMappedBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			System.exit(1);
		} else {
			logger.log(Level.INFO, "Restored!!!");
		}
	}

	/**
	 * Puts the MappedByteBuffer to Helper.STATE_CHECKPOINT and waits for CheckpointRestore.java to change its state to Helper.STATE_RESTORE
	 *
	 * @param b      MappedByteBuffer between the controller process and CheckpointRestore.java
	 * @param logger Logger to log the messages
	 * @param p1     Process object for the client process
	 * @param p2     Process object for the server process
	 */
	static void checkpointAndWait(MappedByteBuffer b, Logger logger, Process p1, Process p2) {
		b.putChar(Helper.MAPPED_INDEX, Helper.STATE_CHECKPOINT);
		char c = b.getChar(Helper.MAPPED_INDEX);
		while (Helper.STATE_CHECKPOINT == c) {
			c = b.getChar(Helper.MAPPED_INDEX);
		}
		if (Helper.STATE_TERMINATE == c) {
			logger.log(Level.SEVERE, "Error during checkpoint-restore, Test terminated");
			b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			p1.destroy();
			p2.destroy();
			System.exit(1);
		}
		if (Helper.STATE_RESTORE != c) {
			logger.log(Level.SEVERE, "Error: Test state is not the expected Restored state");
			b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			p1.destroy();
			p2.destroy();
			System.exit(1);
		}
	}
}
