package controller;

import encryption.*;

import encryption.interfaces.EncryptionAlgorithm;
import encryption.interfaces.SymmetricalEncryptionAlgorithm;
import javafx.event.ActionEvent;
import javafx.fxml.Initializable;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.util.ResourceBundle;

public class MainController implements Initializable {

    enum Status {
        SELECT_FILE("Please select a file"),
        SELECT_ALGORITHM("Please select an algorithm"),
        READY("Ready for de/encryption"),
        ENCRYPTION_SUCCESSFUL("Encryption successful!"),
        DECRYPTION_SUCCESSFUL("Decryption successful!");

        public final String label;

        Status(String label) {
            this.label = label;
        }
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
//        statusLabel.setText(Status.SELECT_FILE.label);
    }
}
