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

class FileRead {
	private static String TESTNAME = "FileRead";

	/**
	 * @param i int value denoting the line number.
	 * @return The line as a string.
	 */
	private static String getLine(int i) {
		return "Line No: " + i + "\n";
	}

	/**
	 * Write in a file, line by line, and read it, checkpoint and restore
	 * and then continue to read and write the file.
	 *
	 * @param args Not used
	 */
	public static void main(String[] args) {
		MappedByteBuffer b = null;
		Logger logger = null;
		int wi, ri = 0;
		try {
			File file = new File(Helper.OUTPUT_FOLDER_NAME + "/" + TESTNAME + "/FileRead_write.txt");
			File f = new File(Helper.MEMORY_MAPPED_FILE_NAME);
			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);
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

			logger.log(Level.INFO, "Checking existence of file to be read and written to.");
			if (file.exists()) {
				file.delete();
			}
			boolean newFile = file.createNewFile();
			if (!newFile) {
				logger.log(Level.SEVERE, "Cannot create a new file to read and write to.");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}

			BufferedWriter brw = new BufferedWriter(new FileWriter(file));
			BufferedReader brr = new BufferedReader(new FileReader(file));

			logger.log(Level.INFO, "Start writing the lines in file");

			for (wi = 1; wi <= 5; wi++) {
				brw.write(getLine(wi));
			}

			brw.flush();
			String s = "Line No: 0";
			int i;

			for (i = 0; i < 50; i++) {
				brw.write(getLine(wi));
				brw.flush();
				wi++;
				s = brr.readLine();
				ri = Integer.parseInt(s.replaceAll("[\\D]", ""));
			}

			wi--;
			logger.log(Level.INFO, "Going to checkpoint");

			/*
			 * Checkpoint and wait for restore
			 */
			Helper.checkpointAndWait(b, logger);
			logger.log(Level.INFO, "Test has been restored!");

			brw.flush();

			try {
				s = brr.readLine();

			} catch (Exception e) {
				logger.log(Level.SEVERE, "Error: Buffered Reader is not reading file");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			if (null == s || s.isEmpty()) {
				logger.log(Level.SEVERE, "Error: Error while reading lines after restore: Line read is null");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			int readLineNo = Integer.parseInt(s.replaceAll("[\\D]", ""));
			if (ri + 1 != readLineNo) {
				logger.log(Level.SEVERE, "Error: Not reading at correct line");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			String ch = brr.readLine();
			while (null != ch && !ch.isEmpty()) {
				s = ch;
				ch = brr.readLine();
			}

			readLineNo = Integer.parseInt(s.replaceAll("[\\D]", ""));

			if (readLineNo != wi) {
				logger.log(Level.SEVERE, "Error: Data written has been lost");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			try {
				brw.write(getLine(wi + 1));
				brw.flush();
			} catch (IOException e) {
				logger.log(Level.SEVERE, "Error: cannot write file after restore");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}

			s = brr.readLine();
			readLineNo = Integer.parseInt(s.replaceAll("[\\D]", ""));

			if (readLineNo != wi + 1) {
				logger.log(Level.SEVERE, "Error: Data not written correctly");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			logger.log(Level.INFO, "File is being read and written to correctly after restore!");
			logger.log(Level.INFO, Helper.PASS_MESSAGE);
			brw.close();
			brr.close();
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
