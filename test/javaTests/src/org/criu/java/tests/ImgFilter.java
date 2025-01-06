package org.criu.java.tests;

import java.io.File;
import java.io.FilenameFilter;

class ImgFilter implements FilenameFilter {
	@Override
	public boolean accept(File dir, String fileName) {
		return (fileName.endsWith(".img"));
	}
}
