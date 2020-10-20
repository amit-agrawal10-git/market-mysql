package com.market.analytics.utility;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


public class ZipUtility {

    public static boolean unZipIt(String zipFileName, String zipFilePath) throws IOException {

        byte[] buffer = new byte[1024];
        ZipInputStream zis = null;
        FileOutputStream fos = null;
        String  zipFile = null;
        File newFile = null;
        try{

            //create output directory is not exists
            File folder = new File(zipFilePath);
            if(!folder.exists()){
                folder.mkdir();
            }

           zipFile = zipFilePath+File.separator+zipFileName;

            //get the zip file content
            zis =
                    new ZipInputStream(new FileInputStream(zipFile));
            //get the zipped file list entry
            ZipEntry ze = zis.getNextEntry();

            while(ze!=null){
                String fileName = ze.getName();
                newFile = new File(zipFilePath + File.separator + fileName);

                //create all non exists folders
                //else you will hit FileNotFoundException for compressed folder
                new File(newFile.getParent()).mkdirs();
                 fos = new FileOutputStream(newFile);

                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                ze = zis.getNextEntry();
            }
        }
        finally {
            if (zis != null){
                zis.closeEntry();
                zis.close();
            }
            if(fos != null){
                fos.close();
            }
            if (zipFile != null)
            new File(zipFile).delete();
        }
        return (newFile != null && newFile.exists());
    }
}
