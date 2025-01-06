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

class MemoryMappings {
	private static String TESTNAME = "MemoryMappings";

	/**
	 * Map a file to memory and write the mapped data into a file,
	 * checkpointing and restoring in between.
	 *
	 * @param args Not used
	 */
	public static void main(String[] args) {
		MappedByteBuffer b = null;
		Logger logger = null;

		try {
			MappedByteBuffer testBuffer;
			char ch;
			int i = 1;
			boolean similar;
			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);
			File f = new File(Helper.MEMORY_MAPPED_FILE_NAME);
			File readFile = new File(Helper.SOURCE_FOLDER + "/" + "ReadWrite.java");
			File writeFile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + TESTNAME + "/" + "MemoryMappings_file.txt");
			RuntimeMXBean bean = ManagementFactory.getRuntimeMXBean();
			String pid = bean.getName();
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
			logger.log(Level.INFO, "Checking existence of file to be memory mapped");
			if (!readFile.exists()) {
				logger.log(Level.SEVERE, "Error: File from which to read does not exist");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}

			channel = FileChannel.open(readFile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			testBuffer = channel.map(MapMode.READ_WRITE, 0, readFile.length());
			channel.close();

			if (writeFile.exists()) {
				writeFile.delete();
			}
			boolean newFile = writeFile.createNewFile();
			if (!newFile) {
				logger.log(Level.SEVERE, "Error: Cannot create a new file to write to.");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}

			BufferedWriter brw = new BufferedWriter(new FileWriter(writeFile));

			while (testBuffer.hasRemaining()) {
				ch = (char) testBuffer.get();
				brw.write(ch);
				i++;
				if (200 == i) {
					logger.log(Level.INFO, "Going to checkpoint");
					Helper.checkpointAndWait(b, logger);
					logger.log(Level.INFO, "Test has been restored!");
				}
			}

			brw.close();
			logger.log(Level.INFO, "Comparing contents of the file");

			similar = Helper.compare(readFile, writeFile);
			if (!similar) {
				logger.log(Level.SEVERE, "Error: Files are not similar after writing");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			logger.log(Level.INFO, "Data was read and written correctly!");
			logger.log(Level.INFO, Helper.PASS_MESSAGE);
			brw.close();
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
