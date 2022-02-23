package controller;

import controller.enums.Status;
import encryption.*;

import encryption.enums.BlockMode;
import encryption.enums.KeyDerivationFunction;
import encryption.enums.PaddingMode;
import encryption.interfaces.PasswordBasedEncryptor;
import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.util.ResourceBundle;

/**
 * Controller for the password_based_encryption.fxml layout
 * Controls UI elements and triggers actions in the {@link PasswordBasedEncryption} class
 *
 * @author Leo Nobis
 */
@SuppressWarnings("ALL")
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
    public ChoiceBox<PasswordBasedEncryptor> cipherChoiceBox;
    public ChoiceBox<KeyDerivationFunction> kdfChoiceBox;
    public ChoiceBox<PaddingMode> paddingModeChoiceBox;
    public ChoiceBox<BlockMode> blockModeChoiceBox;
    public ChoiceBox<Integer> keyLengthChoiceBox;
    public ToggleGroup modeSelectionToggleGroup;
    public Label statusLabel;
    public Label encryptLabel;
    public HBox decryptConfigurationHbox;
    public PasswordField passwordField;
    public Button encryptButton;

    private final PasswordBasedEncryptor[] algorithms = {new PasswordBasedEncryption()};
    private PasswordBasedEncryptor selectedAlgorithm;


    public void onEncryptSelected() {
        mode = Mode.ENCRYPT;
        updateStatus();
        decryptConfigurationHbox.setVisible(false);
        encryptButton.setText("Encrypt");
        encryptLabel.setText("5. Start encryption");
    }

    public void onDecryptSelected() {
        mode = Mode.DECRYPT;
        updateStatus();
        decryptConfigurationHbox.setVisible(true);
        encryptButton.setText("Decrypt");
        encryptLabel.setText("5. Start decryption");
    }

    public void encryptClicked(ActionEvent actionEvent) throws Exception {
        if (updateStatus()) {
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
                        } catch (InvalidAlgorithmParameterException e) {
                            statusLabel.setText(Status.INVALID_PARAMETER_GCM.label);
                        } catch (IllegalBlockSizeException e) {
                            statusLabel.setText(Status.ILLEGAL_BLOCKSIZE.label);
                        } catch (NoSuchPaddingException e) {
                            statusLabel.setText(Status.NO_SUCH_PADDING.label);
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

    private boolean updateStatus() {
        boolean isPasswordSelected = !passwordField.getText().equals("");

        if (isFileSelected) {
            if (mode == Mode.DECRYPT) {
                if (isConfigSelected) {
                    if (isAlgorithmSelected) {
                        if (isPasswordSelected) {
                            statusLabel.setText(Status.READY.label);
                            return true;
                        } else {
                            statusLabel.setText(Status.ENTER_PASSWORD.label);
                        }
                    } else {
                        statusLabel.setText(Status.SELECT_ALGORITHM.label);
                    }
                } else {
                    statusLabel.setText(Status.SELECT_CONFIG.label);
                }
            } else if (mode == Mode.ENCRYPT) {
                if (isAlgorithmSelected) {
                    if (isPasswordSelected) {
                        statusLabel.setText(Status.READY.label);
                        return true;
                    } else {
                        statusLabel.setText(Status.ENTER_PASSWORD.label);
                    }
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
        updateStatus();

        decryptConfigurationHbox.setVisible(false);
        cipherChoiceBox.getItems().addAll(algorithms);
        cipherChoiceBox.setOnAction(actionEvent -> {
            selectedAlgorithm = cipherChoiceBox.getSelectionModel().getSelectedItem();
            isAlgorithmSelected = true;
            updateStatus();

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
        passwordField.setOnKeyTyped(actionEvent -> {
            updateStatus();
        });
    }
}
