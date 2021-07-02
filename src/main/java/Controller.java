import javafx.collections.FXCollections;
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

public class Controller implements Initializable {

    enum Mode {
        ENCRYPT,
        DECRYPT
    }

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

    private File selectedFile;
    private File configurationFile;

    private Mode mode = Mode.ENCRYPT;

    // UI Elements
    public Label selectedFileLabel = null;
    public Label configurationFileLabel;
    public ChoiceBox<EncryptionAlgorithm> cipherChoiceBox;
    public ChoiceBox<PaddingMode> paddingModeChoiceBox;
    public ChoiceBox<BlockMode> blockModeChoiceBox;
    public ToggleGroup modeSelectionToggleGroup;
    public Label statusLabel;
    public HBox decryptConfigurationHbox;

    private final EncryptionAlgorithm[] algorithms = {new AES()};
    private EncryptionAlgorithm selectedAlgorithm;


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
        byte[] outputBytes;
        File outputFile;

        if (selectedFile.exists() && !(selectedAlgorithm == null)) {
            switch (mode) {
                case DECRYPT:
                    outputBytes = selectedAlgorithm.decrypt(Files.readAllBytes(selectedFile.toPath()));
                    statusLabel.setText(Status.DECRYPTION_SUCCESSFUL.label);
                    outputFile = new File(selectedFile.getAbsolutePath());
                    break;
                case ENCRYPT:
                    outputBytes = selectedAlgorithm.encrypt(Files.readAllBytes(selectedFile.toPath()));
                    statusLabel.setText(Status.ENCRYPTION_SUCCESSFUL.label);
                    outputFile = new File(selectedFile.getAbsolutePath() + ".encrypted");
                    break;
                default:
                    outputBytes = null;
                    outputFile = new File(selectedFile.getAbsolutePath());
                    break;
            }
            Files.write(outputFile.toPath(), outputBytes);
        }
    }

    public void browseClicked(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        selectedFile = fileChooser.showOpenDialog(null);
        selectedFileLabel.setText(selectedFile.getAbsolutePath());
        statusLabel.setText(Status.SELECT_ALGORITHM.label);
    }

    public void browseConfigurationClicked(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        configurationFile = fileChooser.showOpenDialog(null);
        configurationFileLabel.setText(configurationFile.getAbsolutePath());
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        statusLabel.setText(Status.SELECT_FILE.label);
        decryptConfigurationHbox.setVisible(false);
        cipherChoiceBox.getItems().addAll(algorithms);
        cipherChoiceBox.setOnAction(actionEvent -> {
            selectedAlgorithm = cipherChoiceBox.getSelectionModel().getSelectedItem();

            paddingModeChoiceBox.setValue(selectedAlgorithm.getSupportedPaddingModes()[0]);
            paddingModeChoiceBox.setItems(FXCollections.observableArrayList(selectedAlgorithm.getSupportedPaddingModes()));

            blockModeChoiceBox.setValue(selectedAlgorithm.getSupportedBlockModes()[0]);
            blockModeChoiceBox.setItems(FXCollections.observableArrayList(selectedAlgorithm.getSupportedBlockModes()));

            statusLabel.setText(Status.READY.label);
        });
    }
}
