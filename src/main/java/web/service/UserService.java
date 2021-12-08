package web.service;


import web.model.User;

import java.util.List;

public interface UserService {

    void addUser(User user);

    void updateUser(User user);

    void deleteUserById(long id);

    User getUserById(long id);

    List<User> getAllUsers();

    User getUserByUsername(String username);

    User getUserByEmail(String email);

    boolean existsUserById(long id);
}
