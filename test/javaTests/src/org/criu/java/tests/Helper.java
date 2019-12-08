package org.criu.java.tests;

import java.io.*;
import java.nio.MappedByteBuffer;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

class Helper {
	static String MEMORY_MAPPED_FILE_NAME = "output/file";
	static String PASS_MESSAGE = "Test was a Success!!!";
	static String OUTPUT_FOLDER_NAME = "output";
	static String PACKAGE_NAME = "org.criu.java.tests";
	static String PID_APPEND = ".pid";
	static String SOURCE_FOLDER = "src/org/criu/java/tests";
	static String LOG_FOLDER = "CRlogs";
	static int MAPPED_REGION_SIZE = 100;
	static int MAPPED_INDEX = 1;
	static char STATE_RESTORE = 'R';
	static char STATE_CHECKPOINT = 'C';
	static char STATE_INIT = 'I';
	static char STATE_TERMINATE = 'T';
	static char STATE_END = 'E';
	static char STATE_FAIL = 'F';
	static char STATE_PASS = 'P';

	/**
	 * Create a new log file and pidfile and write
	 * the pid to the pidFile.
	 *
	 * @param testName Name of the java test
	 * @param pid      Pid of the java test process
	 * @param logger
	 * @return 0 or 1 denoting whether the function was successful or not.
	 * @throws IOException
	 */
	static int init(String testName, String pid, Logger logger) throws IOException {
		File pidfile = new File(OUTPUT_FOLDER_NAME + "/" + testName + "/" + testName + PID_APPEND);

		FileHandler handler = new FileHandler(Helper.OUTPUT_FOLDER_NAME + "/" + testName + "/" + testName + ".log", false);
		handler.setFormatter(new SimpleFormatter());
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
		logger.setLevel(Level.FINE);

		/*
		 * Create a pid file and write the process's pid into it.
		 */
		if (pidfile.exists()) {
			pidfile.delete();
		}
		boolean newFile = pidfile.createNewFile();
		if (!newFile) {
			logger.log(Level.SEVERE, "Cannot create new pid file.");
			return 1;
		}
		BufferedWriter pidWriter = new BufferedWriter(new FileWriter(pidfile));
		pidWriter.write(pid + "\n");
		pidWriter.close();
		return 0;
	}

	/**
	 * Put the Mapped Buffer to 'Ready to be checkpointed' state and wait for restore.
	 *
	 * @param b      The MappedByteBuffer from the calling process.
	 * @param logger The Logger from the calling process.
	 */
	static void checkpointAndWait(MappedByteBuffer b, Logger logger) {
		b.putChar(Helper.MAPPED_INDEX, Helper.STATE_CHECKPOINT);
		char c = b.getChar(Helper.MAPPED_INDEX);
		/*
		 * Loop while MappedByteBuffer is in 'To be checkpointed' state
		 */
		while (Helper.STATE_CHECKPOINT == c) {
			c = b.getChar(Helper.MAPPED_INDEX);
		}
		/*
		 * Test is in 'T' state if some error or exception occurs during checkpoint or restore.
		 */
		if (Helper.STATE_TERMINATE == c) {
			logger.log(Level.SEVERE, "Error during checkpoint-restore, Test terminated");
			b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			System.exit(1);
		}
		/*
		 * The expected state of MappedByteBuffer is Helper.STATE_RESTORE-restored state.
		 */
		if (Helper.STATE_RESTORE != c) {
			logger.log(Level.INFO, "Error: Test state is not the expected Restored state");
			b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			System.exit(1);
		}
	}


	/**
	 * Compare two files and return true if their content is similar.
	 *
	 * @param readFile  File 1 whose content has to be compared.
	 * @param writeFile File 2 whose content has to be compared.
	 * @return true if the files are similar, false otherwise.
	 * @throws IOException
	 */
	static boolean compare(File readFile, File writeFile) throws IOException {
		BufferedReader bir = new BufferedReader(new FileReader(readFile));
		BufferedReader bor = new BufferedReader(new FileReader(writeFile));
		String si, so;
		si = bir.readLine();
		so = bor.readLine();
		while (null != si && null != so) {
			if (!si.equals(so)) {
				return false;
			}

			si = bir.readLine();
			so = bor.readLine();
		}

		if ((null == si) && (null == so)) {
			return true;
		}
		bir.close();
		bor.close();

		return false;
	}

}
