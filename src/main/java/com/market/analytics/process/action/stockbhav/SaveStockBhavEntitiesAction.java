package com.market.analytics.process.action.stockbhav;

import com.market.analytics.entity.Stock;
import com.market.analytics.entity.StockBhav;
import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.process.context.Context;
import com.market.analytics.utility.Constants;
import org.apache.commons.csv.CSVRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;

import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SaveStockBhavEntitiesAction {

    private static final Logger logger = LoggerFactory.getLogger(SaveStockBhavEntitiesAction.class);

    /**
     *
     * @param context
     * @param taskTemplate
     * @param input - List<CSVRecords>
     * @return null
     * @throws Exception
     */
    public static Object execute(Context context, TaskTemplate taskTemplate, Object input) throws Exception {
        List<CSVRecord> csvRecords = (List<CSVRecord>)input;
        Map<String,Stock> code2StockMap = getCode2StockMapping(context.getScripManager().getAllStocks());
        StockBhav stockBhav = null;

        for (CSVRecord csvRecord:csvRecords) {
            stockBhav = new StockBhav(
                    (Date)context.getContextValue("date"),
                    Double.parseDouble(csvRecord.get(Constants.StockBhav.OPEN)),
                    Double.parseDouble(csvRecord.get(Constants.StockBhav.CLOSE)),
                    Double.parseDouble(csvRecord.get(Constants.StockBhav.HIGH)),
                    Double.parseDouble(csvRecord.get(Constants.StockBhav.LOW)),
                    Double.parseDouble(csvRecord.get(Constants.StockBhav.PREVCLOSE)),
                    code2StockMap.get(csvRecord.get(Constants.StockBhav.SYMBOL)),
                    Double.parseDouble(csvRecord.get(Constants.StockBhav.TOTTRDVAL)),
                    new BigInteger(csvRecord.get(Constants.StockBhav.TOTTRDQTY)),
                    new BigInteger(csvRecord.get(Constants.StockBhav.TOTALTRADES))
                    );
            try {
                context.getManager().save(stockBhav);
            } catch (DataIntegrityViolationException exception){
                logger.debug("entry already exists");
            }
        }
        logger.debug("Stock Bhav saved");
        return null;
    }

    private static Map<String,Stock> getCode2StockMapping(List<Stock> stocks){
        Map<String,Stock> stringStockMap = new HashMap();
        stocks.forEach(s -> stringStockMap.put(s.getCode(),s));
        return stringStockMap;
    }

}
