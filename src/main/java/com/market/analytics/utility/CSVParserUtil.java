package com.market.analytics.utility;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Component;

import java.io.FileReader;
import java.io.IOException;
import java.util.List;

public class CSVParserUtil {

    public static List<CSVRecord> parseCSVFile(String fileName, String[] FILE_HEADER_MAPPING) throws Exception {
        CSVParser csvFileParser = null;
        List<CSVRecord> records = null;
        try {
            FileReader fileReader = new FileReader(fileName);
            CSVFormat csvFileFormat = CSVFormat.DEFAULT.withHeader(FILE_HEADER_MAPPING);
            csvFileParser = new CSVParser(fileReader, csvFileFormat);
            records = csvFileParser.getRecords();
        } finally {
            if (csvFileParser != null)
                csvFileParser.close();
        }
        return records;
    }

}
