package main;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;

public class Utilities {

	public static void writeTimeResults(String result,String path) {
		File log = new File(path);
		try{
			FileWriter fileWriter = new FileWriter(log, true);
			BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
			bufferedWriter.write(result+ "\n");
			bufferedWriter.close();
		} catch(IOException e) {
			System.out.println("COULD NOT LOG!!");
		}		
	}

	public static File[] readFiles(String path){
		File directoryPath = new File(path);
		File filesList[] = directoryPath.listFiles();
		return filesList;
	}
	
	
	public static void writeOnDisk(String path, byte[]data) {
		File file = new File(path);
		try {
			OutputStream os = new FileOutputStream(file);
			os.write(data);
			os.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void deleteFiles(String path) {
		File directoryPath = new File(path);
		File[] files = directoryPath.listFiles();
	    if(files != null) {
	        for ( File file : files) {
	            file.delete();
	        }
	    }
	}

}
