package com.market.analytics.controller;

import com.market.analytics.entity.Stock;
import com.market.analytics.service.Manager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.math.BigInteger;
import java.util.List;

@Controller
@RequestMapping("/tstockt")
public class StockController {

    private static final Logger logger = LoggerFactory.getLogger(StockController.class);

    @Autowired
    Manager<Stock, BigInteger> manager;

    @GetMapping("/list")
    public String listStock(Model model) {
        List<Stock> stocks = manager.getObjects(Stock.class);
        model.addAttribute("listStock",stocks);
        return "home";
    }
}
