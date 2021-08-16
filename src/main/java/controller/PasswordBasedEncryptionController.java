package controller;

import encryption.*;

import encryption.enums.BlockMode;
import encryption.enums.KeyDerivationFunction;
import encryption.enums.PaddingMode;
import encryption.interfaces.PasswordBasedEncryptionAlgorithm;
import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.fxml.Initializable;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;

import javax.crypto.AEADBadTagException;
import java.io.File;
import java.net.URL;
import java.util.ResourceBundle;


public class PasswordBasedEncryptionController implements Initializable {

    enum Mode {
        ENCRYPT,
        DECRYPT
    }

    private boolean isFileSelected = false;
    private boolean isConfigSelected = false;
    private boolean isAlgorithmSelected = false;

    private File selectedFile;
    private File configurationFile;

    private Mode mode = Mode.ENCRYPT;

    // UI Elements
    public Label selectedFileLabel = null;
    public Label configurationFileLabel;
    public ChoiceBox<PasswordBasedEncryptionAlgorithm> cipherChoiceBox;
    public ChoiceBox<KeyDerivationFunction> kdfChoiceBox;
    public ChoiceBox<PaddingMode> paddingModeChoiceBox;
    public ChoiceBox<BlockMode> blockModeChoiceBox;
    public ChoiceBox<Integer> keyLengthChoiceBox;
    public ToggleGroup modeSelectionToggleGroup;
    public Label statusLabel;
    public HBox decryptConfigurationHbox;
    public PasswordField passwordField;

    private final PasswordBasedEncryptionAlgorithm[] algorithms = {new PasswordBasedEncryption()};
    private PasswordBasedEncryptionAlgorithm selectedAlgorithm;


    public void onEncryptSelected() {
        mode = Mode.ENCRYPT;
        decryptConfigurationHbox.setVisible(false);
        System.out.println("Encrypt selected");
    }

    public void onDecryptSelected() {
        mode = Mode.DECRYPT;
        decryptConfigurationHbox.setVisible(true);
        System.out.println("Decrypt selected");
    }

    public void encryptClicked(ActionEvent actionEvent) throws Exception {
        if (selectedFile.exists() && !(selectedAlgorithm == null)) {
            selectedAlgorithm.init(
                    paddingModeChoiceBox.getValue(),
                    blockModeChoiceBox.getValue(),
                    kdfChoiceBox.getValue(),
                    keyLengthChoiceBox.getValue(),
                    selectedFile,
                    configurationFile,
                    passwordField.getText()
            );

            switch (mode) {
                case DECRYPT:
                    try {
                        selectedAlgorithm.decrypt();
                        statusLabel.setText(Status.DECRYPTION_SUCCESSFUL.label);
                    } catch (AEADBadTagException e) {
                        statusLabel.setText(Status.WRONG_PASSWORD.label);
                    } catch (Exception e) {
                        statusLabel.setText(Status.DECRYPTION_FAILED.label);
                        throw e;
                    }
                    break;
                case ENCRYPT:
                    try {
                        selectedAlgorithm.encrypt();
                        statusLabel.setText(Status.ENCRYPTION_SUCCESSFUL.label);
                    } catch (Exception e) {
                        statusLabel.setText(Status.ENCRYPTION_FAILED.label);
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
        selectedFileLabel.setText(selectedFile.getAbsolutePath());
//        statusLabel.setText(Status.SELECT_ALGORITHM.label);
    }

    public void browseConfigurationClicked(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        configurationFile = fileChooser.showOpenDialog(null);
        configurationFileLabel.setText(configurationFile.getAbsolutePath());
    }

    private boolean updateStatus() {
        if (isFileSelected) {
            if (mode == Mode.DECRYPT) {
                if (isConfigSelected) {
                    if (isAlgorithmSelected) {
                        statusLabel.setText(Status.READY.label);
                        return true;
                    } else {
                        statusLabel.setText(Status.SELECT_ALGORITHM.label);
                    }
                } else {
                    statusLabel.setText(Status.SELECT_CONFIG.label);
                }
            } else if (mode == Mode.ENCRYPT) {
                if (isAlgorithmSelected) {
                    statusLabel.setText(Status.READY.label);
                    return true;
                } else {
                    statusLabel.setText(Status.SELECT_ALGORITHM.label);
                }
            }
        } else {
            statusLabel.setText(Status.SELECT_FILE.label);
        }
        return false;
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        decryptConfigurationHbox.setVisible(false);
        cipherChoiceBox.getItems().addAll(algorithms);
        cipherChoiceBox.setOnAction(actionEvent -> {
            selectedAlgorithm = cipherChoiceBox.getSelectionModel().getSelectedItem();

            kdfChoiceBox.setValue(selectedAlgorithm.getSupportedKdf()[0]);

            paddingModeChoiceBox.setValue(selectedAlgorithm.getSupportedPaddingModes()[0]);
            paddingModeChoiceBox.setItems(FXCollections.observableArrayList(selectedAlgorithm.getSupportedPaddingModes()));

            blockModeChoiceBox.setValue(selectedAlgorithm.getSupportedBlockModes()[0]);
            blockModeChoiceBox.setItems(FXCollections.observableArrayList(selectedAlgorithm.getSupportedBlockModes()));

            kdfChoiceBox.setValue(selectedAlgorithm.getSupportedKdf()[0]);
            kdfChoiceBox.setItems(FXCollections.observableArrayList(selectedAlgorithm.getSupportedKdf()));

            keyLengthChoiceBox.setValue(selectedAlgorithm.getSupportedKeyLengths()[0]);
            keyLengthChoiceBox.setItems(FXCollections.observableArrayList(selectedAlgorithm.getSupportedKeyLengths()));
        });
    }
}
