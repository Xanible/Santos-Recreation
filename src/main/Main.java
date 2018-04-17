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
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

public class Main {

	public static void main(String[] args) throws IOException {
		//Setup
		HashMap<String, Double> opcodeWeights = new HashMap<String, Double>();
		File malDir = new File("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\Cleaned Disassembly\\Malware");
		File benDir = new File("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\Cleaned Disassembly\\Benign");

		//Get opcode Weights from file
		getWeights(opcodeWeights);
		
		//Read in list of pairs
		BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\Pairing Lists\\Pair"  + 1 + ".txt"));
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
		BufferedWriter arff = new BufferedWriter(new FileWriter("C:/Users/colby/Desktop/SCHOOL/AndroidCT/Weighted_Sequences.arff"));
		arff.write("@relation Benign-Malware");
		arff.newLine();
		arff.newLine();
		arff.write("@attribute @@class@@ {Benign,Malware}");
		arff.newLine();
		for(String s: opcodePairList){
			arff.write("@attribute \"" + s + "\" numeric");
			arff.newLine();
		}
		arff.newLine();
		arff.write("@data");
		arff.newLine();
		
		//Read in List of files to test
		BufferedReader br2 = new BufferedReader(new FileReader("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\File Lists\\Master List.txt"));
		List<String> malFileList = new ArrayList<String>();
		List<String> benFileList = new ArrayList<String>();
		br2.readLine();
		int incrementer = 1;
		for (String line = br2.readLine(); line != null; line = br2.readLine()) {
			if(incrementer < 1001) {
				malFileList.add(line);
				incrementer++;
			} else if(incrementer == 1001) {
				System.out.println(line);
				br2.readLine();
				benFileList.add(br2.readLine());
				incrementer++;
			} else {
				benFileList.add(line);
				incrementer++;
			}
		}
		br2.close();	

		
		//Sequencing loops
		int counter = 1;
		for(String s: malFileList) {
			System.out.println(counter);
			try {
				//Output file name
				System.out.println(s);
				
				//Read in a file
				String filePath = malDir.getPath() + "\\" +s;
				File f = new File(filePath);
				
				List<String> theFile = Files.readAllLines(f.toPath(), Charset.defaultCharset() );
				String[] words = theFile.get(0).split(" ");
				List<String> opcodes = new ArrayList<String>(Arrays.asList(words));
				
				//Send file through sequencer
				HashMap<String, Integer> sequencesCount = new HashMap<String,Integer>(sequencesMasterList);
				int totalSequences = 0;
				for(int i = 0;i < opcodes.size() - 1;i++) {
					String o = opcodes.get(i) + " " + opcodes.get(i + 1);
					if(sequencesCount.containsKey(o)) {
						int currentVal = sequencesCount.get(o);
						currentVal++;
						sequencesCount.put(o, currentVal);
						totalSequences++;
					} else {
						System.out.println(o);
						System.exit(0);
					}
				}
				
				//Determine the Weighted Frequencies
				HashMap<String, Double> sequencesWeighted = new HashMap<String, Double>(sequencesWeightedMasterList);
				for(String op: opcodePairList){
					int count = sequencesCount.get(op);
					double frequency = ((double) count)/totalSequences;
					String[] opcodesInPair = op.split(" ");
					double opcode1Weight, opcode2Weight;
					if(opcodeWeights.containsKey(opcodesInPair[0])){
						opcode1Weight = opcodeWeights.get(opcodesInPair[0]);
					}else {
						opcode1Weight = 0;
						System.out.println(opcodesInPair[0]);
					}
					if(opcodeWeights.containsKey(opcodesInPair[1])){
						opcode2Weight = opcodeWeights.get(opcodesInPair[1]);
					}else {
						opcode2Weight = 0;
						System.out.println(opcodesInPair[1]);
					}
					double part = (opcode1Weight/100) * (opcode2Weight/100);
					double weightedFrequency = frequency * part;
					sequencesWeighted.put(op, weightedFrequency);
				}
				
				
				//Print out sequence frequency file
				arff.write("Malware");
				for(String op: opcodePairList){
					DecimalFormat df = new DecimalFormat("0", DecimalFormatSymbols.getInstance(Locale.ENGLISH));
					df.setMaximumFractionDigits(340); // 340 = DecimalFormat.DOUBLE_FRACTION_DIGITS

					double scale = 100000000000000.0;
					arff.write("," + df.format(sequencesWeighted.get(op) * scale));
				}
				arff.newLine();
				counter++;
				
			} catch (IOException e) {
				System.out.println("Error reading from malware file!");
				e.printStackTrace();
			}
		}
		
		//Benign
		counter = 1;
		for(String s: benFileList) {
			System.out.println(counter);
			try {
				//Output file name
				System.out.println(s);
				
				//Read in a file
				String filePath = benDir.getPath() + "\\" +s;
				File f = new File(filePath);
				
				List<String> theFile = Files.readAllLines(f.toPath(), Charset.defaultCharset() );
				String[] words = theFile.get(0).split(" ");
				List<String> opcodes = new ArrayList<String>(Arrays.asList(words));

				//Send file through sequencer
				HashMap<String, Integer> sequencesCount = new HashMap<String,Integer>(sequencesMasterList);
				int totalSequences = 0;
				for(int i = 0;i < opcodes.size() - 1;i++) {
					String o = opcodes.get(i) + " " + opcodes.get(i + 1);
					if(sequencesCount.containsKey(o)) {
						int currentVal = sequencesCount.get(o);
						currentVal++;
						sequencesCount.put(o, currentVal);
						totalSequences++;
					} else {
						System.out.println(o);
						System.exit(0);
					}
				}

				//Determine the Weighted Frequencies
				HashMap<String, Double> sequencesWeighted = new HashMap<String, Double>(sequencesWeightedMasterList);
				for(String op: opcodePairList){
					int count = sequencesCount.get(op);
					double frequency = ((double) count)/totalSequences;
					String[] opcodesInPair = op.split(" ");
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
					sequencesWeighted.put(op, weightedFrequency);
				}


				//Print out sequence frequency file
				arff.write("Benign");
				for(String op: opcodePairList){
					DecimalFormat df = new DecimalFormat("0", DecimalFormatSymbols.getInstance(Locale.ENGLISH));
					df.setMaximumFractionDigits(340); // 340 = DecimalFormat.DOUBLE_FRACTION_DIGITS

					double scale = 100000000000000.0;
					arff.write("," + df.format(sequencesWeighted.get(op) * scale));
				}
				arff.newLine();
				counter++;

			} catch (IOException e) {
				System.out.println("Error reading from benign file!");
				e.printStackTrace();
			}
		}
		arff.close();
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