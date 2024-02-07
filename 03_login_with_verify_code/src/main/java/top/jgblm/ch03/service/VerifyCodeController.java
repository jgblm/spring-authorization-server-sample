package top.jgblm.ch03.service;

import com.google.code.kaptcha.Producer;
import jakarta.annotation.Resource;
import java.awt.image.BufferedImage;
import java.io.IOException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.imageio.ImageIO;

@RestController
public class VerifyCodeController {
  @Resource Producer producer;

  @GetMapping("/vc.jpg")
  public void getVerifyCode(HttpServletResponse resp, HttpSession session) throws IOException {
    resp.setContentType("image/jpeg");
    String text = producer.createText();
    session.setAttribute("verify_code", text);
    BufferedImage image = producer.createImage(text);
    try (ServletOutputStream out = resp.getOutputStream()) {
      ImageIO.write(image, "jpg", out);
    }
  }
}
