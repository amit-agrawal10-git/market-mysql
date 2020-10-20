package com.market.analytics.process.initiater;

import com.market.analytics.entity.process.Process;
import com.market.analytics.process.context.Context;

public abstract class Processor implements Executable {

    private Process process;
    private Context context;

    public Context getContext() {
        return context;
    }

    public void setContext(Context context) {
        this.context = context;
    }

    public Process getProcess() {
        return process;
    }

    public void setProcess(Process process) {
        this.process = process;
    }
}
