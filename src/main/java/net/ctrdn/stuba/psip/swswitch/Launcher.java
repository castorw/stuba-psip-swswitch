package net.ctrdn.stuba.psip.swswitch;

import net.ctrdn.stuba.psip.swswitch.core.SwitchController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Launcher implements Runnable {

    private final Logger logger = LoggerFactory.getLogger(Launcher.class);
    private SwitchController switchController;
    private Thread switchControllerThread;

    public Launcher() {
    }

    @Override
    public void run() {
        this.logger.info("Software Switch is starting up");
        this.switchController = new SwitchController();
        this.switchController.initialize();
        this.switchControllerThread = new Thread(this.switchController);
        this.switchControllerThread.start();
    }

    public static void main(String[] argv) {
        Launcher launcher = new Launcher();
        launcher.run();
    }
}
