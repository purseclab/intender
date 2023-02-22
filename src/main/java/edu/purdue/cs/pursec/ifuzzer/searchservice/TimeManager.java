package edu.purdue.cs.pursec.ifuzzer.searchservice;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

/**
 * @author Apoorv Shukla and saidjawadsaidi
 *
 */
public class TimeManager {
    ArrayList<Long> times;
    FileWriter fw ;
    BufferedWriter bw;
    int counter ;

    public TimeManager(){
        times = new ArrayList<Long>();
        try{
            long startTimeNano, taskTimeNano;
            //Specify the file name and path here
            File file =new File("myfile.txt");

            /* This logic is to create the file if the
             * file is not already present
             */
            if(!file.exists()){
                file.createNewFile();
            }
            //Here true is to append the content to file
            fw = new FileWriter(file,true);
            //BufferedWriter writer give better performance
            bw = new BufferedWriter(fw);



            //System.out.println("Data successfully appended at the end of file");

        }catch(IOException ioe){
            //System.out.println("Exception occurred:");
            ioe.printStackTrace();
        }
    }
    public void append(long taskTimeNano){
        try{
            if(counter >=100){

                bw.close();
                fw.close();
                File file =new File("myfile.txt");

                fw = new FileWriter(file,true);
                //BufferedWriter writer give better performance
                bw = new BufferedWriter(fw);
                counter = 0;

            }
            else{
                counter += 1;
            }
            times.add(taskTimeNano);
            String value = Long.toString(taskTimeNano);
            value += "\n";

            bw.write(value);
            bw.flush();

        }catch(IOException ioe){
            ioe.printStackTrace();

        }
    }
}
