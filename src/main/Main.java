package main;

/* 
 *  This program generates a weka database file based on dalvik pairs using the 
 *  Classification features from the Santos paper.
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;

public class Main {

	public static void main(String[] args) throws IOException {
		//Setup
		HashMap<String, Double> opcodeWeights = new HashMap<String, Double>();
		File malDir = new File("C:\\Users\\colby\\Desktop\\AndroidCT\\Cleaned Disassembly\\Malware");
		File benDir = new File("C:\\Users\\colby\\Desktop\\AndroidCT\\Cleaned Disassembly\\Benign");
		File[] malArray = malDir.listFiles();
		File[] benArray = benDir.listFiles();
		List<File> malFiles = new ArrayList<File>(Arrays.asList(malArray));
		List<File> benFiles = new ArrayList<File>(Arrays.asList(benArray));

		//Get opcode Weights from file
		getWeights(opcodeWeights);
		
		//Read in list of pairs
		BufferedReader br = new BufferedReader(new FileReader("C:/Users/colby/Desktop/School/ADCT/Dalvik_Opcode_Pair_List.txt"));
		List<String> opcodePairList = new ArrayList<String>();
		for (String line = br.readLine(); line != null; line = br.readLine()) {
			opcodePairList.add(line);
		}
		br.close();	
		
		//Create master hashmaps
		HashMap<String, Integer> sequencesMasterList = new HashMap<String, Integer>();
		for(String s: opcodePairList){
			sequencesMasterList.put(s, 0);
		}
		HashMap<String, Double> sequencesWeightedMasterList = new HashMap<String, Double>();
		for(String s: opcodePairList){
			sequencesWeightedMasterList.put(s, 0.0);
		}
		
		//Prepare the arff file
		BufferedWriter arff = new BufferedWriter(new FileWriter("C:/Users/colby/Desktop/AndroidCT/Weighted_Sequences.arff"));
		arff.write("@relation Malware-Benign");
		arff.newLine();
		arff.newLine();
		arff.write("@attribute @@class@@ {Malware,Benign}");
		arff.newLine();
		for(String s: opcodePairList){
			arff.write("@attribute \"" + s + "\" numeric");
			arff.newLine();
		}
		arff.newLine();
		arff.write("@data");
		arff.newLine();
		
		//Create list files for reference
		BufferedWriter referList = new BufferedWriter(new FileWriter("C:/Users/colby/Desktop/AndroidCT/List of Files.txt"));
		referList.write("Malware:");
		referList.newLine();
		
		//Initialize random generator
		Random randomGenerator = new Random();
		
		//Sequencing loops
		for(int counter = 0; counter < 1000; counter++) {
			System.out.println(counter);
			try {
				//Get a random file
				int index = randomGenerator.nextInt(malFiles.size());
				File f = malFiles.get(index);
				malFiles.remove(index);
				
				//Output file name
				referList.write(f.getName());
				System.out.println(f.getName());
				referList.newLine();
				
				//Read in a file
				List<String> theFile = Files.readAllLines(f.toPath(), Charset.defaultCharset() );
				String[] words = theFile.get(0).split(" ");
				List<String> opcodes = new ArrayList<String>(Arrays.asList(words));
				
				//Send file through sequencer
				HashMap<String, Integer> sequencesCount = sequencesMasterList;
				int totalSequences = 0;
				for(int i = 0;i < opcodes.size() - 1;i++) {
					String s = opcodes.get(i) + " " + opcodes.get(i + 1);
					if(sequencesCount.containsKey(s)) {
						int currentVal = sequencesCount.get(s);
						currentVal++;
						sequencesCount.put(s, currentVal);
						totalSequences++;
					} else {
						System.out.println(s);
						System.exit(0);
					}
				}
				
				//Determine the Weighted Frequencies
				HashMap<String, Double> sequencesWeighted = sequencesWeightedMasterList;
				for(String s: opcodePairList){
					int count = sequencesCount.get(s);
					double frequency = count/totalSequences;
					String[] opcodesInPair = s.split(" ");
					double opcode1Weight, opcode2Weight;
					if(opcodeWeights.containsKey(opcodesInPair[0])){
						opcode1Weight = opcodeWeights.get(opcodesInPair[0]);
					}else {
						opcode1Weight = 0;
					}
					if(opcodeWeights.containsKey(opcodesInPair[1])){
						opcode2Weight = opcodeWeights.get(opcodesInPair[1]);
					}else {
						opcode2Weight = 0;
					}
					double part = (opcode1Weight/100) * (opcode2Weight/100);
					double weightedFrequency = frequency * part;
					sequencesWeighted.put(s, weightedFrequency);
				}
				
				
				//Print out sequence frequency file
				arff.write("Malware");
				for(String s: opcodePairList){
					arff.write("," + Double.toString(sequencesWeighted.get(s)));
				}
				arff.newLine();
				
			} catch (IOException e) {
				System.out.println("Error reading from malware file!");
			}
		}

		referList.newLine();
		referList.write("Benign:");
		referList.newLine();
		
		for(int counter = 0; counter < 1000; counter++) {
			System.out.println(counter);
			try {
				//Get a random file
				int index = randomGenerator.nextInt(benFiles.size());
				File f = benFiles.get(index);
				benFiles.remove(index);
				
				//Output file name
				referList.write(f.getName());
				referList.newLine();
				
				//Read in a file
				List<String> theFile = Files.readAllLines(f.toPath(), Charset.defaultCharset() );
				String[] words = theFile.get(0).split(" ");
				List<String> opcodes = new ArrayList<String>(Arrays.asList(words));

				//Send file through sequencer
				HashMap<String, Integer> sequencesCount = sequencesMasterList;
				int totalSequences = 0;
				for(int i = 0;i < opcodes.size() - 1;i++) {
					String s = opcodes.get(i) + " " + opcodes.get(i + 1);
					if(sequencesCount.containsKey(s)) {
						int currentVal = sequencesCount.get(s);
						currentVal++;
						sequencesCount.put(s, currentVal);
						totalSequences++;
					} else {
						System.out.println(s);
						System.exit(0);
					}
				}

				//Determine the Weighted Frequencies
				HashMap<String, Double> sequencesWeighted = sequencesWeightedMasterList;
				for(String s: opcodePairList){
					int count = sequencesCount.get(s);
					double frequency = count/totalSequences;
					String[] opcodesInPair = s.split(" ");
					double opcode1Weight, opcode2Weight;
					if(opcodeWeights.containsKey(opcodesInPair[0])){
						opcode1Weight = opcodeWeights.get(opcodesInPair[0]);
					}else {
						opcode1Weight = 0;
					}
					if(opcodeWeights.containsKey(opcodesInPair[1])){
						opcode2Weight = opcodeWeights.get(opcodesInPair[1]);
					}else {
						opcode2Weight = 0;
					}
					double part = (opcode1Weight/100) * (opcode2Weight/100);
					double weightedFrequency = frequency * part;
					sequencesWeighted.put(s, weightedFrequency);
				}


				//Print out sequence frequency file
				arff.write("Benign");
				for(String s: opcodePairList){
					arff.write("," + Double.toString(sequencesWeighted.get(s)));
				}
				arff.newLine();

			} catch (IOException e) {
				System.out.println("Error reading from benign file!");
				e.printStackTrace();
			}
		}
		arff.close();
		referList.close();
	}

	public static void getWeights(HashMap<String, Double> opcodeWeights) {
		try {
			BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\colby\\Desktop\\School\\ADCT\\Dalvik Opcodes InfoGain.txt"));
			for (String line = br.readLine(); line != null; line = br.readLine()) {
				String[] s = line.split(" ");
				opcodeWeights.put(s[s.length - 1], Double.parseDouble(s[0]));
			}
			br.close();
		} catch (FileNotFoundException e) {
			System.out.println("Error opening weight file!");
		} catch (IOException e) {
			System.out.println("Error reading from weight file!");
		}
	}

}