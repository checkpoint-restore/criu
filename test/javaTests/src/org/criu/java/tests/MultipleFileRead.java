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

class MultipleFileRead {
	private static String TESTNAME = "MultipleFileRead";

	/**
	 * @param readFile1 File 1 whose contents are read.
	 * @param readFile2 File 2 whose contents are read.
	 * @param writeFile File in which data has been written to.
	 * @return true if the data written is as expected, false otherwise.
	 * @throws IOException
	 */
	private static boolean compare(File readFile1, File readFile2, File writeFile) throws IOException {
		BufferedReader br1 = new BufferedReader(new FileReader(readFile1));
		BufferedReader br2 = new BufferedReader(new FileReader(readFile2));
		BufferedReader brw = new BufferedReader(new FileReader(writeFile));
		boolean eof1, eof2;
		eof1 = false;
		eof2 = false;
		String inpString, wrtString;

		while (!eof1 || !eof2) {
			if (!eof1) {
				inpString = br1.readLine();
				if (null == inpString) {
					eof1 = true;
				} else {
					wrtString = brw.readLine();
					if (null == wrtString) {
						return false;
					}
					if (!wrtString.equals(inpString)) {
						return false;
					}
				}
			}
			if (!eof2) {
				inpString = br2.readLine();
				if (null == inpString) {
					eof2 = true;
				} else {
					wrtString = brw.readLine();
					if (null == wrtString) {
						return false;
					}
					if (!wrtString.equals(inpString)) {
						return false;
					}
				}
			}
		}

		wrtString = brw.readLine();
		if (null != wrtString) {
			return false;
		}

		br1.close();
		br2.close();
		brw.close();

		return true;
	}

	/**
	 * Read from multiple files and write their content into another file,
	 * checkpointing and restoring in between.
	 *
	 * @param args Not used.
	 */
	public static void main(String[] args) {
		MappedByteBuffer b = null;
		String s;
		int i = 0;
		Logger logger = null;
		try {
			logger = Logger.getLogger(Helper.PACKAGE_NAME + "." + TESTNAME);
			File f = new File(Helper.MEMORY_MAPPED_FILE_NAME);
			File readFile1 = new File(Helper.SOURCE_FOLDER + "/" + "FileRead.java");
			File readFile2 = new File(Helper.SOURCE_FOLDER + "/" + "ReadWrite.java");
			File writeFile = new File(Helper.OUTPUT_FOLDER_NAME + "/" + TESTNAME + "/" + "MultipleFileRead_file.txt");
			boolean eofFile1 = false, eofFile2 = false, check;
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
			if (b.getChar(Helper.MAPPED_INDEX) != Helper.STATE_INIT) {
				logger.log(Level.SEVERE, "Error: Error in memory mapping, test is not in init state");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			logger.log(Level.INFO, "Checking existence of the read files");

			if (!readFile1.exists()) {
				logger.log(Level.SEVERE, "Error: File from which to read does not exist");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			if (!readFile2.exists()) {
				logger.log(Level.SEVERE, "Error: File from which to read does not exist");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}
			if (writeFile.exists()) {
				writeFile.delete();
			}
			logger.log(Level.INFO, "Creating writeFile");
			boolean newFile = writeFile.createNewFile();
			if (!newFile) {
				logger.log(Level.SEVERE, "Error: Cannot create a new file to write to.");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_END);
				System.exit(1);
			}

			BufferedReader br1 = new BufferedReader(new FileReader(readFile1));
			BufferedReader br2 = new BufferedReader(new FileReader(readFile2));
			BufferedWriter brw = new BufferedWriter(new FileWriter(writeFile));

			logger.log(Level.INFO, "Writing in file");

			while (!eofFile1 || !eofFile2) {
				if (!eofFile1) {
					s = br1.readLine();
					i++;
					if (null == s) {
						eofFile1 = true;
					} else {
						brw.write(s + "\n");
					}
				}
				if (!eofFile2) {
					s = br2.readLine();
					i++;
					if (null == s) {
						eofFile2 = true;
					} else {
						brw.write(s + "\n");
					}
				}
				if (10 == i) {
					/*
					 * Checkpoint and Restore
					 */
					logger.log(Level.INFO, "Going to checkpoint");
					Helper.checkpointAndWait(b, logger);
					logger.log(Level.INFO, "Test has been restored!");
				}
			}
			brw.flush();
			logger.log(Level.INFO, "Checking the content of the file");
			check = compare(readFile1, readFile2, writeFile);

			if (!check) {
				logger.log(Level.SEVERE, "Error: Files are not similar after writing");
				b.putChar(Helper.MAPPED_INDEX, Helper.STATE_FAIL);
				System.exit(1);
			}
			logger.log(Level.INFO, "The file has been written as expected");
			logger.log(Level.INFO, Helper.PASS_MESSAGE);
			br1.close();
			br2.close();
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
