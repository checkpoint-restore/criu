package org.criu.java.tests;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.StandardOpenOption;
import java.util.logging.Level;
import java.util.logging.Logger;

class MultipleFileWrite {
	private static String TESTNAME = "MultipleFileWrite";

	/**
	 * Reads from a file and write its content into multiple files,
	 * checkpointing and restoring in between.
	 *
	 * @param args Not used.
	 */
	public static void main(String[] args) {
		MappedByteBuffer b = null;
		String s, pid;
		int i = 1;
		Logger logger = null;
		boolean similar1, similar2;
		try {
			File readFile = new File(Helper.SOURCE_FOLDER + "/" + "FileRead.java");
			File writeFile1 = new File(Helper.OUTPUT_FOLDER_NAME + "/" + TESTNAME + "/" + TESTNAME + "1_file.txt");
			File writeFile2 = new File(Helper.OUTPUT_FOLDER_NAME + "/" + TESTNAME + "/" + TESTNAME + "2_file.txt");
			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);
			File f = new File(Helper.MEMORY_MAPPED_FILE_NAME);
			RuntimeMXBean bean = ManagementFactory.getRuntimeMXBean();
			pid = bean.getName();
			int val = Helper.init(TESTNAME, pid, logger);
			if (0 != val) {
				logger.log(Level.SEVERE, "Helper.init returned a non-zero code.");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			logger.log(Level.INFO, "Test init done; pid written to pid file; beginning with test");

			FileChannel channel = FileChannel.open(f.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			b = channel.map(MapMode.READ_WRITE, 0, Helper.MAPPED_REGION_SIZE);
			channel.close();
			/*
			 * Mapped Byte Buffer should be in init state at the beginning of test
			 */
			if (Helper.STATE_INIT != b.getChar(Helper.MAPPED_INDEX)) {
				logger.log(Level.SEVERE, "Error: Error in memory mapping, test is not in init state");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			logger.log(Level.INFO, "Checking existence of read files!");

			if (!readFile.exists()) {
				logger.log(Level.SEVERE, "Error: File from which to read does not exist");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			if (writeFile1.exists()) {
				writeFile1.delete();
			}
			boolean newFile = writeFile1.createNewFile();
			if (!newFile) {
				logger.log(Level.SEVERE, "Error: Cannot create a new file to write to.");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}

			if (writeFile2.exists()) {
				writeFile2.delete();
			}
			newFile = writeFile2.createNewFile();
			if (!newFile) {
				logger.log(Level.SEVERE, "Error: Cannot create a new file to write to.");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			logger.log(Level.INFO, "Created write files");

			BufferedReader br = new BufferedReader(new FileReader(readFile));
			BufferedWriter bw1 = new BufferedWriter(new FileWriter(writeFile1));
			BufferedWriter bw2 = new BufferedWriter(new FileWriter(writeFile2));

			s = br.readLine();

			while (null != s) {
				bw1.write(s + "\n");
				bw2.write(s + "\n");
				if (90 == i) {
					/*
					 * Checkpoint and Restore
					 */
					logger.log(Level.INFO, "Going to checkpoint");
					Helper.checkpointAndWait(b, logger);
					logger.log(Level.INFO, "Test has been restored!");
				}

				i++;
				s = br.readLine();
			}

			bw1.flush();
			bw2.flush();
			logger.log(Level.INFO, "Checking files have been written correctly");

			similar1 = Helper.compare(readFile, writeFile1);
			similar2 = Helper.compare(readFile, writeFile2);

			if (!similar1 || !similar2) {
				logger.log(Level.SEVERE, "Error: Written data is not identical to the data read");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			logger.log(Level.INFO, "Content of files is as expected");
			logger.log(Level.INFO, Helper.PASS_MESSAGE);
			br.close();
			bw1.close();
			bw2.close();
			b.putChar(Helper.MAPPED_INDEX, Helper.STATE_PASS);
			System.exit(0);

		} catch (Exception e) {
			if (null != logger) {
				StringWriter writer = new StringWriter();
				PrintWriter printWriter = new PrintWriter(writer);
				e.printStackTrace(printWriter);
				logger.log(Level.SEVERE, "Exception occurred:" + e);
				logger.log(Level.FINE, writer.toString());
			}

			if (null != b) {
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
			}
			System.exit(5);
		}
	}
}
