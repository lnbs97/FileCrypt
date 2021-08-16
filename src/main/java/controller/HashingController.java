package controller;

import encryption.Hashing;
import encryption.HashAlgorithm;
import javafx.event.ActionEvent;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.net.URL;
import java.util.ResourceBundle;

public class HashingController implements Initializable {

    enum Mode {
        HASH,
        CHECK_HASH
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
    public ChoiceBox<HashAlgorithm> cipherChoiceBox;

    private Mode mode = Mode.HASH;

    private boolean isFileSelected = false;
    private boolean isConfigSelected = false;

    private HashAlgorithm selectedAlgorithm;
    private Hashing hashing = new Hashing();

    public void encryptClicked(ActionEvent actionEvent) throws Exception {
        if (updateStatus()) {
            switch (mode) {
                case CHECK_HASH:
                    try {
                        if (hashing.check_hash(selectedFile, configurationFile)) {
                            statusLabel.setText(Status.HASH_CHECK_SUCCESS.label);
                        } else {
                            statusLabel.setText(Status.HASH_CHECK_FAILED.label);
                        }
                    } catch
                    (Exception e) {
                        statusLabel.setText(Status.HASH_CHECK_FAILED.label);
                        throw e;
                    }
                    break;
                case HASH:
                    try {
                        File outputFile = new File(selectedFile.getAbsolutePath() + "_hash.json");
                        hashing.hash(selectedFile, outputFile, selectedAlgorithm);
                        statusLabel.setText(Status.HASH_SUCCESSFUL.label);
                    } catch (Exception e) {
                        statusLabel.setText(Status.HASH_FAILED.label);
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
            updateStatus();
        } else {
            selectedFileLabel.setText("No file selected");
            isFileSelected = false;
            updateStatus();
        }
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
        mode = Mode.HASH;
        updateStatus();
        decryptConfigurationHbox.setVisible(false);
        encryptButton.setText("Hash");
        encryptLabel.setText("3. Start hashing");
    }

    public void onVerifySelected() {
        mode = Mode.CHECK_HASH;
        updateStatus();
        decryptConfigurationHbox.setVisible(true);
        encryptButton.setText("Check");
        encryptLabel.setText("3. Check hash");
    }

    private boolean updateStatus() {
        if (isFileSelected) {
            if (mode == Mode.CHECK_HASH) {
                if (isConfigSelected) {
                    statusLabel.setText(Status.READY_SIGNING.label);
                    return true;
                } else {
                    statusLabel.setText(Status.SELECT_HASH_FILE.label);
                }
            } else if (mode == Mode.HASH) {
                statusLabel.setText(Status.READY_HASH.label);
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

        selectedAlgorithm = HashAlgorithm.values()[0];
        decryptConfigurationHbox.setVisible(false);
        cipherChoiceBox.getItems().addAll(HashAlgorithm.values());
        cipherChoiceBox.setValue(HashAlgorithm.values()[0]);
        cipherChoiceBox.setOnAction(actionEvent -> {
            selectedAlgorithm = cipherChoiceBox.getValue();
            updateStatus();
        });
    }
}
