package com.example.demo.controller;

import com.example.demo.model.Rating;
import com.example.demo.service.RatingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/recipes")
public class RatingController {

    @Autowired
    private RatingService ratingService;

    @PostMapping("/{recipeId}/rate/{userId}/{ratingValue}")
    public ResponseEntity<Rating> rateRecipe(
            @PathVariable("recipeId") Long recipeId,
            @PathVariable("userId") Long userId,
            @PathVariable Integer ratingValue) {
        Rating rating = ratingService.rateRecipe(recipeId, userId, ratingValue);
        return ResponseEntity.ok(rating);
    }

    @DeleteMapping("/{recipeId}/rate/{userId}")
    public ResponseEntity<String> deleteRating(@PathVariable Long recipeId, @PathVariable Long userId) {
        ratingService.deleteRating(recipeId, userId);
        return ResponseEntity.ok("Rating deleted successfully.");
    }


}
