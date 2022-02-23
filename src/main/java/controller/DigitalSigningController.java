package controller;

import controller.enums.Status;
import encryption.DigitalSigning;
import javafx.event.ActionEvent;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.net.URL;
import java.util.ResourceBundle;

/**
 * Controller for the digital_signing.fxml layout
 * Controls UI elements and triggers actions in the {@link DigitalSigning} class
 *
 * @author Leo Nobis
 */
@SuppressWarnings("ALL")
public class DigitalSigningController implements Initializable {

    enum Mode {
        SIGN,
        VERIFY
    }

    private File selectedFile;
    private File configurationFile;

    public Label selectedFileLabel = null;
    public Label configurationFileLabel;
    public Label statusLabel;
    public Label encryptLabel;
    public ToggleGroup modeSelectionToggleGroup;
    public HBox decryptConfigurationHbox;
    public Button encryptButton;

    private Mode mode = Mode.SIGN;

    private boolean isFileSelected = false;
    private boolean isConfigSelected = false;

    public void encryptClicked(ActionEvent actionEvent) throws Exception {
        if (updateStatus()) {
            switch (mode) {
                case VERIFY:
                    try {
                        if(DigitalSigning.verify(selectedFile, configurationFile)) {
                            statusLabel.setText(Status.VERIFY_SUCCESSFUL.label);
                        } else {
                            statusLabel.setText(Status.VERIFY_FAILED.label);
                        }
                    } catch
                    (Exception e) {
                        statusLabel.setText(Status.VERIFY_FAILED.label);
                        throw e;
                    }
                    break;
                case SIGN:
                    try {
                        File outputFile = new File(selectedFile.getAbsolutePath() + "_sig.json");
                        DigitalSigning.sign(selectedFile, outputFile);
                        statusLabel.setText(Status.SIGNING_SUCCESSFUL.label);
                    } catch (Exception e) {
                        statusLabel.setText(Status.SIGNING_FAILED.label);
                        throw e;
                    }
                    break;
                default:
                    break;
            }
        }
    }

    public void browseClicked(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        selectedFile = fileChooser.showOpenDialog(null);
        if (selectedFile != null) {
            selectedFileLabel.setText(selectedFile.getAbsolutePath());
            isFileSelected = true;
        } else {
            selectedFileLabel.setText("No file selected");
            isFileSelected = false;
        }
        updateStatus();
    }

    public void browseConfigurationClicked(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        configurationFile = fileChooser.showOpenDialog(null);
        if (configurationFile != null) {
            isConfigSelected = true;
            updateStatus();
            configurationFileLabel.setText(configurationFile.getAbsolutePath());
        } else {
            configurationFileLabel.setText("No configuration file selected");
            isConfigSelected = false;
            updateStatus();
        }
    }

    public void onSignSelected() {
        mode = Mode.SIGN;
        updateStatus();
        decryptConfigurationHbox.setVisible(false);
        encryptButton.setText("Sign");
        encryptLabel.setText("3. Start signing");
    }

    public void onVerifySelected() {
        mode = Mode.VERIFY;
        updateStatus();
        decryptConfigurationHbox.setVisible(true);
        encryptButton.setText("Verify");
        encryptLabel.setText("3. Start signature verification");
    }

    private boolean updateStatus() {
        if (isFileSelected) {
            if (mode == Mode.VERIFY) {
                if (isConfigSelected) {
                    statusLabel.setText(Status.READY_SIGNING.label);
                    return true;
                } else {
                    statusLabel.setText(Status.SELECT_CONFIG.label);
                }
            } else if (mode == Mode.SIGN) {
                statusLabel.setText(Status.READY_SIGNING.label);
                return true;
            }
        } else {
            statusLabel.setText(Status.SELECT_FILE.label);
        }
        return false;
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        updateStatus();
        decryptConfigurationHbox.setVisible(false);
    }
}
