package com.example.demo.service;

import com.example.demo.exception.ResourceNotFoundException;
import com.example.demo.model.Rating;
import com.example.demo.model.Recipe;
import com.example.demo.model.User;
import com.example.demo.repository.RatingRepository;
import com.example.demo.repository.RecipeRepository;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RatingService {

    @Autowired
    private RatingRepository ratingRepository;

    @Autowired
    private RecipeRepository recipeRepository;

    @Autowired
    private UserRepository userRepository;


    public Rating rateRecipe(Long recipeId, Long userId, Integer ratingValue) {
        Recipe recipe = recipeRepository.findById(recipeId)
                .orElseThrow(() -> new ResourceNotFoundException("Recipe not found with ID: " + recipeId));
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

//        if (ratingRepository.existsByRecipeIdAndUserId(recipeId, userId)) {
//            throw new IllegalArgumentException("User has already rated this recipe.");
//        }

        List<Recipe> recipiesRatedByUser =  recipe.getUser().getRecipes();

        System.err.println(recipiesRatedByUser.get(0));


        Boolean isPresent= recipiesRatedByUser.stream().map(Recipe::getRecipeId).peek(System.err::println).anyMatch(a->(a==recipeId));

        List<Rating> ratings =recipe.getRatings();
        for(Rating r : ratings) {
            Long us =  r.getUser().getUserId();
            Long re = r.getRecipe().getRecipeId();

            if ( us == userId && re == recipeId) {
                throw new ResourceNotFoundException("User has already rated this Recipe");
            }


        }


        Rating rating = new Rating();
        rating.setRecipe(recipe);
        rating.setUser(user);
        rating.setRating(ratingValue);
        return ratingRepository.save(rating);


    }


    public void deleteRating(Long recipeId, Long userId) {
        Rating rating = ratingRepository.findById(recipeId)
                .orElseThrow(() -> new ResourceNotFoundException("Rating not found for the recipe ID: " + recipeId));

        if (!rating.getUser().getUserId().equals(userId)) {
            throw new IllegalArgumentException("Only the user who created the rating can delete it.");
        }

        ratingRepository.delete(rating);
    }


}