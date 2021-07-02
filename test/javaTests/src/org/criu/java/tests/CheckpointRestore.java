package org.criu.java.tests;

import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.*;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CheckpointRestore {
	private MappedByteBuffer mappedByteBuffer = null;
	private String testName = "";
	private String logFolder = Helper.LOG_FOLDER + "/";
	private String outputFolder = Helper.OUTPUT_FOLDER_NAME + "/";

	/**
	 * Create CRlog and output directory if they don't exist.
	 * Delete directories containing .img files from failed Checkpoint-Restore if 'neverCleanFailures' property is not set to true.
	 *
	 * @throws IOException
	 */
	@BeforeSuite
	void suiteSetup() throws IOException {
		System.out.println("Tests are to be run as a privileged user having capabilities mentioned in ReadMe");
		boolean neverCleanFailures = Boolean.getBoolean("neverCleanFailures");
		Path logDir = Paths.get(logFolder);
		Path outputDir = Paths.get(outputFolder);
		if (!Files.exists(logDir)) {
			System.out.println("Logs directory does not exist, creating it");
			Files.createDirectory(logDir);
		}
		if (!Files.exists(outputDir)) {
			System.out.println("Output directory does not exist, creating it");
			Files.createDirectory(outputDir);
		}
		/*
		 * Delete the directories containing the img files from failed Checkpoint-Restore.
		 */
		if (!neverCleanFailures) {
			File output = new File(outputFolder);
			String[] name = output.list();
			for (int i = 0; null != name && i < name.length; i++) {
				File testFolder = new File(outputFolder + name[i]);
				if (testFolder.isDirectory()) {
					String[] list = testFolder.list();
					File file;
					if (null != list) {
						for (int j = 0; j < list.length; j++) {
							file = new File(outputFolder + name[i] + "/" + list[j]);
							if (!file.isDirectory()) {
								Files.delete(file.toPath());
							}
						}
					}
				}
				Files.delete(testFolder.toPath());
			}
		}
	}

	/**
	 * Create the output folder for the test in case it does not exist
	 *
	 * @param testName Name of the java test
	 * @throws IOException
	 */
	private void testSetup(String testName) throws IOException {
		Path testFolderPath = Paths.get(outputFolder + testName + "/");
		if (!Files.exists(testFolderPath)) {
			System.out.println("Creating the test folder");
			Files.createDirectory(testFolderPath);
		}
	}

	/**
	 * Read the pid of process from the pid file of test
	 *
	 * @param name Name of the java test
	 * @return pid Process id of the java test process
	 * @throws IOException
	 */
	private String getPid(String name) throws IOException {
		name = outputFolder + testName + "/" + name + Helper.PID_APPEND;
		File pidfile = new File(name);
		BufferedReader pidReader = new BufferedReader(new FileReader(pidfile));
		String pid = pidReader.readLine();
		pidReader.close();
		return pid;
	}

	/**
	 * @param testName      Name of the java test
	 * @param checkpointOpt Additional options for checkpoint
	 * @param restoreOpt    Additional options for restore
	 * @throws Exception
	 */
	@Test
	@Parameters({"testname", "checkpointOpt", "restoreOpt"})
	public void runtest(String testName, String checkpointOpt, String restoreOpt) throws Exception {
		this.testName = testName;
		String name = Helper.PACKAGE_NAME + "." + testName;
		String pid;
		int exitCode;

		System.out.println("======= Testing " + testName + " ========");

		testSetup(testName);

		File f = new File(Helper.MEMORY_MAPPED_FILE_NAME);
		if (f.exists()) {
			f.delete();
		}

		/*
		 * Create a new file that will be mapped to memory and used to communicate between
		 * this process and the java test process.
		 */
		boolean newFile = f.createNewFile();
		Assert.assertTrue(newFile, "Unable to create a new file to be mapped");

		/*
		 * MappedByteBuffer communicates between this process and java process called.
		 */
		FileChannel channel = FileChannel.open(f.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
		mappedByteBuffer = channel.map(MapMode.READ_WRITE, 0, Helper.MAPPED_REGION_SIZE);
		mappedByteBuffer.clear();
		channel.close();

		/*
		 * Put MappedByteBuffer in Init state
		 */
		mappedByteBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_INIT);

		/*
		 * Run the test as a separate process
		 */
		System.out.println("Starting the java Test");
		ProcessBuilder builder = new ProcessBuilder("java", "-cp", "target/classes", name);
		Process process = builder.start();

		char currentState = mappedByteBuffer.getChar(Helper.MAPPED_INDEX);
		/*
		 * Loop until the test process changes the state of MappedByteBuffer from init state
		 */
		while (Helper.STATE_INIT == currentState) {
			currentState = mappedByteBuffer.getChar(Helper.MAPPED_INDEX);
			Thread.sleep(100);
		}

		/*
		 * If Mapped Buffer is in Helper.STATE_FAIL state before checkpointing then an exception must
		 * have occurred in the test.
		 */
		while (Helper.STATE_FAIL == currentState) {
			try {
				/*
				 * We exit the test process with exit code 5 in case of an exception
				 */
				exitCode = process.exitValue();
				/*
				 * Reaching here implies that .exitValue() has not thrown an exception, so the process has
				 * exited, We now check the exitCode.
				 */
				if (5 == exitCode) {
					Assert.fail(testName + ": Exception occurred while running the test: check the log file for details.");
				} else {
					Assert.fail(testName + ": ERROR: Unexpected value of exit code: " + exitCode + ", expected: 5");
				}
			} catch (IllegalThreadStateException e) {
				/*
				 * Do nothing, as an Exception is expected if the process has not exited
				 * and we try to get its exitValue.
				 */
			}

			currentState = mappedByteBuffer.getChar(Helper.MAPPED_INDEX);
		}

		/*
		 * Mapped Buffer state should be Helper.STATE_CHECKPOINT for checkpointing or Helper.STATE_END if some error occurs in test
		 */
		if (Helper.STATE_END != currentState) {
			Assert.assertEquals(currentState, Helper.STATE_CHECKPOINT, testName + ": ERROR: Error occurred while running the test: test is not in the excepted 'waiting to be checkpointed state': " + currentState);
		} else {
			Assert.fail(testName + ": ERROR: Error took place in the test check the log file for more details");
		}
		/*
		 * Reaching here implies that MappedByteBuffer is in To Be Checkpointed state.
		 * Get the pid of the test process
		 */

		pid = getPid(testName);
		try {
			/*
			 * Checkpoint the process
			 */
			checkpoint(pid, checkpointOpt);

		} catch (Exception e) {
			/*
			 * If exception occurs put the MappedByteBuffer to Helper.STATE_TERMINATE-Terminate state.
			 * On reading the terminate state, the test process terminates, else it
			 * may go on looping.
			 */
			mappedByteBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_TERMINATE);
			Assert.fail(testName + ": Exception occurred while during checkpointing" + e, e);
		}

		/*
		 * The process has been checkpointed successfully, now restoring the process.
		 */
		try {
			/*
			 * Restore the process
			 */
			restore(restoreOpt);
		} catch (Exception e) {
			mappedByteBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_TERMINATE);
			Assert.fail(testName + ": Exception occurred while restoring the test" + e, e);
		}

		/*
		 * Wait for test process to finish
		 */
		currentState = mappedByteBuffer.getChar(Helper.MAPPED_INDEX);
		while (Helper.STATE_RESTORE == currentState) {
			currentState = mappedByteBuffer.getChar(Helper.MAPPED_INDEX);
		}

		/*
		 * If a test passes it puts the MappedByteBuffer to Helper.STATE_PASS-Pass state,
		 * On failing to Helper.STATE_FAIL-Fail state, and if our Buffer is in Helper.STATE_TERMINATE state
		 * its because the checkpoint-restore of test process failed.
		 */

		Assert.assertNotEquals(currentState, Helper.STATE_TERMINATE, testName + ": ERROR: Checkpoint-Restore failed");
		Assert.assertNotEquals(currentState, Helper.STATE_FAIL, testName + ": ERROR: Test Failed, Check Log for details");
		Assert.assertEquals(currentState, Helper.STATE_PASS, testName + " ERROR: Unexpected State of Mapped Buffer");
		System.out.println("----- " + "PASS" + " -----");

	}

	/**
	 * Remove .img files, dump.log, restore.log, stats-dump and stats-restore files from Log Directory
	 *
	 * @throws IOException
	 */
	@AfterTest
	void cleanup() throws IOException {
		int i;
		String currentPath = System.getProperty("user.dir");
		currentPath = currentPath + "/" + logFolder;
		File deleteFile;
		File dir = new File(currentPath);
		String[] imgFiles = dir.list(new ImgFilter());
		if (null != imgFiles) {
			for (i = 0; i < imgFiles.length; i++) {
				deleteFile = new File(currentPath + imgFiles[i]);
				Files.delete(deleteFile.toPath());
			}
		}

		boolean exists = Files.exists(Paths.get(currentPath + "dump.log"));
		if (exists) {
			Files.delete(Paths.get(currentPath + "dump.log"));
		}

		exists = Files.exists(Paths.get(currentPath + "restore.log"));
		if (exists) {
			Files.delete(Paths.get(currentPath + "restore.log"));
		}

		exists = Files.exists(Paths.get(currentPath + "stats-dump"));
		if (exists) {
			Files.delete(Paths.get(currentPath + "stats-dump"));
		}

		exists = Files.exists(Paths.get(currentPath + "stats-restore"));
		if (exists) {
			Files.delete(Paths.get(currentPath + "stats-restore"));
		}
	}

	/**
	 * Copy .img files, dump.log, restore.log, stats-dump and stats-restore files from Log Directory if they exist
	 * to another folder.
	 *
	 * @throws IOException
	 */
	String copyFiles() throws IOException {
		String currentPath = System.getProperty("user.dir");
		String folderSuffix = new SimpleDateFormat("yyMMddHHmmss").format(new Date());
		String fromPath = currentPath + "/" + logFolder;
		File fromDir = new File(fromPath);
		Path fromFile, toFile;
		boolean exists;
		String toPath = currentPath + "/" + outputFolder + testName + folderSuffix + "/";
		Path dirPath = Paths.get(toPath);
		Files.createDirectory(dirPath);

		String[] imgFiles = fromDir.list(new ImgFilter());
		if (null != imgFiles) {
			for (int i = 0; i < imgFiles.length; i++) {
				fromFile = Paths.get(fromPath + imgFiles[i]);
				toFile = Paths.get(toPath + imgFiles[i]);
				Files.copy(fromFile, toFile);
			}
		}

		fromFile = Paths.get(fromPath + "dump.log");
		exists = Files.exists(fromFile);
		if (exists) {
			toFile = Paths.get(toPath + "dump.log");
			Files.copy(fromFile, toFile);
		}

		fromFile = Paths.get(fromPath + "restore.log");
		exists = Files.exists(fromFile);
		if (exists) {
			toFile = Paths.get(toPath + "restore.log");
			Files.copy(fromFile, toFile);
		}

		fromFile = Paths.get(fromPath + "stats-dump");
		exists = Files.exists(fromFile);
		if (exists) {
			toFile = Paths.get(toPath + "stats-dump");
			Files.copy(fromFile, toFile);
		}

		fromFile = Paths.get(fromPath + "stats-restore");
		exists = Files.exists(fromFile);
		if (exists) {
			toFile = Paths.get(toPath + "stats-restore");
			Files.copy(fromFile, toFile);
		}

		return folderSuffix;
	}

	/**
	 * Checkpoint the process, if process has not been checkpointed correctly
	 * copy the .img, log and stats files, puts MappedBuffer to 'terminate' state and mark
	 * test as failed
	 *
	 * @param pid           Pid of process to be checkpointed
	 * @param checkpointOpt Additional options for checkpoint
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private void checkpoint(String pid, String checkpointOpt) throws IOException, InterruptedException {
		ProcessBuilder builder;
		System.out.println("Checkpointing process " + pid);
		String command = "../../criu/criu dump --shell-job -t " + pid + " --file-locks -v4 -D " + logFolder + " -o dump.log";
		if (0 == checkpointOpt.length()) {
			String[] cmd = command.split(" ");
			builder = new ProcessBuilder(cmd);
		} else {
			command = command + " " + checkpointOpt;
			String[] cmd = command.split(" ");
			builder = new ProcessBuilder(cmd);
		}
		Process process = builder.start();
		BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
		int exitCode = process.waitFor();

		if (0 != exitCode) {
			/*
			 * Print the error stream
			 */
			String line = stdError.readLine();
			while (null != line) {
				System.out.println(line);
				line = stdError.readLine();
			}

			mappedByteBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_TERMINATE);
			/*
			 * If checkpoint fails copy the img files, dump.log, stats-dump, stats-restore
			 */
			String folderSuffix = copyFiles();

			Assert.fail(testName + ": ERROR: Error during checkpoint: exitCode of checkpoint process was not zero.\nFor more details check dump.log in " + outputFolder + testName + folderSuffix);
			return;
		}

		System.out.println("Checkpoint success");
		process.destroy();

	}

	/**
	 * Restore the process, if process has been restored correctly put Mapped Buffer to
	 * 'restored' state, else copy the .img, log and stats files and put MappedBuffer to 'terminate'
	 * state and mark test as failed
	 *
	 * @param restoreOpt Additional options for restore
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private void restore(String restoreOpt) throws IOException, InterruptedException {
		ProcessBuilder builder;
		System.out.println("Restoring process");
		String command = "../../criu/criu restore -d --file-locks -v4 --shell-job -D " + logFolder + " -o restore.log";
		if (0 == restoreOpt.length()) {
			String[] cmd = command.split(" ");
			builder = new ProcessBuilder(cmd);
		} else {
			command = command + " " + restoreOpt;
			String[] cmd = command.split(" ");
			builder = new ProcessBuilder(cmd);
		}

		Process process = builder.start();
		BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
		int exitCode = process.waitFor();

		if (0 != exitCode) {
			/*
			 * Print the error stream
			 */
			String line = stdError.readLine();
			while (null != line) {
				System.out.println(line);
				line = stdError.readLine();
			}
			mappedByteBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_TERMINATE);
			/*
			 * If restore fails copy img files, dump.log, restore.log, stats-dump, stats-restore
			 */
			String folderSuffix = copyFiles();
			Assert.fail(testName + ": ERROR: Error during restore: exitCode of restore process was not zero.\nFor more details check restore.log in " + outputFolder + testName + folderSuffix);

			return;
		} else {
			System.out.println("Restore success");
			mappedByteBuffer.putChar(Helper.MAPPED_INDEX, Helper.STATE_RESTORE);
		}
		process.destroy();
	}
}
