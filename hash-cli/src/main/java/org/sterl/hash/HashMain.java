package org.sterl.hash;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

public class HashMain {

    private final static Options options = new Options();
    static {
        options.addOption("a", true, "Algrorithmus one of " + Arrays.toString(Algorithm.values()));
        //options.addOption("m", "method", false, "HTTP method to use.");
        //options.addOption("p", "payload", false, "String payload to send.");
        options.addOption("p", "password", true, "Password to hash.");
        options.addOption("h", "hash", true, "The hash to check the passwort against. Note you may have to escape $ with an \\.");
    }
    public static void main(String[] args) {
        Algorithm algorithm = Algorithm.BCrypt;
        String password = "";
        String hash = null;

        if (args.length > 1) {
            final CommandLineParser parser = new DefaultParser();
            try {
                final CommandLine cmd = parser.parse(options, args);
                
                if (cmd.hasOption('a')) {
                    algorithm = Algorithm.valueOf(cmd.getOptionValue('a'));
                }
                password = cmd.getOptionValue('p');
                
                if (cmd.hasOption('h')) {
                    hash = cmd.getOptionValue('h');
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
                System.exit(-1);
            }
        } else if (args.length == 1) {
            password = args[0];
        } else {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("hash-cli", options);
            System.exit(-1);
        }
        if (hash == null) {
            System.out.println(new BCryptPbkdf2PasswordHash(algorithm).encode(password));
        } else {
            System.out.println(new BCryptPbkdf2PasswordHash(algorithm).matches(password, hash));
        }
    }

}
