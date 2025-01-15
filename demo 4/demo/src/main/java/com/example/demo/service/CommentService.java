package com.example.demo.service;


import com.example.demo.exception.ResourceNotFoundException;
import com.example.demo.exception.UnauthorizedAccessException;
import com.example.demo.model.Comment;
import com.example.demo.model.Recipe;
import com.example.demo.model.User;
import com.example.demo.repository.CommentRepository;
import com.example.demo.repository.RecipeRepository;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CommentService {

    @Autowired
    private CommentRepository commentRepository;

    @Autowired
    private RecipeRepository recipeRepository;

    @Autowired
    private UserRepository userRepository;

    public Comment addComment(Long recipeId, Long userId, String content) {
        Recipe recipe = recipeRepository.findById(recipeId)
                .orElseThrow(() -> new ResourceNotFoundException("Recipe not found"));
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Comment comment = new Comment();
        comment.setRecipe(recipe);
        comment.setUser(user);
        comment.setContent(content);

        return commentRepository.save(comment);
    }

    public List<Comment> getCommentsByRecipe(Long recipeId) {
        Recipe recipe = recipeRepository.findById(recipeId)
                .orElseThrow(() -> new ResourceNotFoundException("Recipe not found"));

        return commentRepository.findByRecipe(recipe);
    }



    public List<Comment> getCommentsByUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        return commentRepository.findByUser(user);
    }
//    public Comment updateComment(Long recipeId, Long commentId, Long userId, String newContent) {
//
//        Recipe recipe = recipeRepository.findById(recipeId)
//                .orElseThrow(() -> new ResourceNotFoundException("Recipe not found with ID: " + recipeId));
//
//
//        Comment comment = commentRepository.findById(commentId)
//                .orElseThrow(() -> new ResourceNotFoundException("Comment not found with ID: " + commentId));
//
//
//        if (!comment.getRecipe().getRecipeId().equals(recipe)) {
//            throw new ResourceNotFoundException("Comment does not belong to the specified recipe");
//        }
//
//
//        User user = userRepository.findById(userId)
//                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));
//
//
//        if (!comment.getUser().getUserId().equals(user)) {
//            throw new UnauthorizedAccessException("User not authorized to update this comment");
//        }
//
//
//        comment.setContent(newContent);
//        return commentRepository.save(comment);
//    }


    public void deleteComment(Long recipeId, Long commentId, Long userId) {

        System.err.println("RECIPE+ "+recipeId +" Comment "+commentId+"  user "+userId );

        Recipe recipe = recipeRepository.findById(recipeId)
                .orElseThrow(() -> new ResourceNotFoundException("Recipe not found with ID: " + recipeId));


        Comment comment = commentRepository.findById(commentId)
                .orElseThrow(() -> new ResourceNotFoundException("Comment not found with ID: " + commentId));


        if (!(comment.getRecipe().getRecipeId()==recipe.getRecipeId())) {
            throw new ResourceNotFoundException("Comment does not belong to the specified recipe");
        }


        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));


        if (!(comment.getUser().getUserId()==user.getUserId())){
            throw new UnauthorizedAccessException("User not authorized to delete this comment");
        }


        commentRepository.delete(comment);
    }

}
