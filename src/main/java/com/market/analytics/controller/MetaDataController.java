package com.market.analytics.controller;

import com.market.analytics.entity.metadata.Attribute;
import com.market.analytics.entity.metadata.AttributeType;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@Controller
@RequestMapping("/metadata")
public class MetaDataController {

    @GetMapping("/param/new")
    public String newParam(Model model){
        model.addAttribute("attr",new Attribute());
        model.addAttribute("attr_type", AttributeType.values());
        return "attr-form";
    }

    @PostMapping(value = "/param/save")
    public String saveParam(@ModelAttribute("attr") Attribute attribute){
        System.out.println(attribute);
        return "attr-form";
    }


}
