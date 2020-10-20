package com.market.analytics.process.action.stockbhav;

import com.market.analytics.entity.Stock;
import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.process.context.Context;
import com.market.analytics.utility.Constants;
import org.apache.commons.csv.CSVRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

public class StockBhavFilterAction {

    private static final Logger logger = LoggerFactory.getLogger(StockBhavFilterAction.class);

    /**
     *
     * @param context
     * @param taskTemplate
     * @param input - List<CSVRecords>
     * @return Stream<CSVRecords>
     * @throws Exception
     */
    public static Object execute(Context context, TaskTemplate taskTemplate, Object input) throws Exception {
        List<CSVRecord> csvRecords = (List<CSVRecord>)input;
        List<String> codes = context.getScripManager().getAllScripCodesByClass(Stock.class);
        List<CSVRecord> filteredRecords = csvRecords.
                stream()
                .filter(r -> r.get(Constants.StockBhav.SERIES).equals("EQ"))
                .filter(s -> codes.contains(s.get(Constants.StockBhav.SYMBOL)))
                .collect(Collectors.toList());
                ;
        if (filteredRecords.size()==0)
            throw new RuntimeException("Nothing found after filter");

        logger.debug("Filtered CSV Record count "+filteredRecords.size());
        return filteredRecords;
    }

}
